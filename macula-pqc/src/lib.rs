//! The facade: the one place macula's post-quantum posture is decided.
//!
//! # API
//!
//! [`client_builder`] and [`server_builder`]: rustls configuration
//! builders with the crypto provider and TLS 1.3 already fixed. The caller
//! chooses certificates, the verifier, client authentication and ALPN. It
//! cannot choose the key exchange groups or the signature algorithms.
//!
//! [`self_signed_certificate`]: a self-signed ML-DSA-87 certificate and
//! its PKCS#8 key from a 32-byte seed, the form a macula node keeps its
//! TLS key in.
//!
//! [`KeyPossessionVerifier`]: a server certificate verifier for such a
//! certificate, and the one a macula client dials a station with. It
//! accepts exactly one certificate whose key is ML-DSA-87, then the
//! server's handshake signature under that key. It proves the server holds
//! the key, not who the server is: the caller binds the key to an identity.
//!
//! # Getting started
//!
//! Depend on `macula-pqc` and nothing else for TLS. Build each rustls
//! configuration from one of the two builders, then carry on as with any
//! rustls builder: the key exchange groups and the signature algorithms
//! are the only things already decided.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let seed = [7u8; 32];
//! // A server certificate and key: ML-DSA-87, from a seed.
//! let (certificate, private_key) =
//!     macula_pqc::self_signed_certificate(&seed, vec!["localhost".to_string()])?;
//!
//! // A client: you choose how the server is verified.
//! let mut roots = rustls::RootCertStore::empty();
//! roots.add(certificate.clone())?;
//! let mut client = macula_pqc::client_builder()
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! client.alpn_protocols = vec![b"macula".to_vec()];
//!
//! // A server: you choose client authentication and the certificate.
//! let server = macula_pqc::server_builder()
//!     .with_no_client_auth()
//!     .with_single_cert(vec![certificate], private_key.into())?;
//!
//! // Both offer SecP384r1MLKEM1024, then SecP256r1MLKEM768, and nothing
//! // else, and both verify ML-DSA-87 signatures and nothing else.
//! assert_eq!(client.crypto_provider().kx_groups.len(), 2);
//! assert_eq!(server.crypto_provider().kx_groups.len(), 2);
//! assert_eq!(
//!     client.crypto_provider().signature_verification_algorithms.supported_schemes(),
//!     vec![rustls::SignatureScheme::ML_DSA_87]
//! );
//! # Ok(())
//! # }
//! ```
//!
//! For QUIC, hand the result to quinn as usual, for example
//! `quinn::crypto::rustls::QuicClientConfig::try_from(client)`. QUIC
//! requires TLS 1.3, which both builders already fix.
//!
//! # Why a facade, and why the posture lives here
//!
//! The `kx_groups` list IS the post-quantum posture: which groups are
//! offered, in what order, and that nothing classical-only is among them.
//! That is policy, not QUIC plumbing, so it does not belong in a QUIC
//! transport crate.
//!
//! `macula_quic` and `macula-rust` each used to select a crypto provider
//! themselves. Two copies of one posture is a contract in two places: one
//! of them eventually gains a classical fallback and nothing notices. Both
//! now build their TLS configurations from here, on their default
//! branches.
//!
//! # ⚠ How far "locked" goes, stated precisely
//!
//! - **What is locked:** no function here returns a `CryptoProvider`. The
//!   provider goes straight into a rustls builder, which keeps it in a
//!   private field and offers only a read-only view (`crypto_provider()`),
//!   and so does every configuration built from it. Nothing a caller
//!   receives lets it add or remove a group, and the groups themselves are
//!   not re-exported.
//! - **What is not, and cannot be:** rustls is a public crate. A caller
//!   that depends on it directly can build a configuration from scratch
//!   with any provider, or clone ours out of the read-only view and build
//!   a new one. Both bypass this crate entirely: a deliberate act, visible
//!   in review, not an edit to something this crate handed out. Nothing in
//!   Rust can prevent that, and claiming otherwise would be the same
//!   defect as a guard that cannot fire.
//!
//! So the guarantee is: **every configuration built from this crate offers
//! exactly our list**, and the tests beside the list assert that of the
//! builders themselves, including the negative control that makes the
//! posture checkable rather than merely documented.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use rustls::{ClientConfig, ConfigBuilder, ServerConfig, WantsVerifier};

mod key_possession;
mod signatures;

pub use key_possession::KeyPossessionVerifier;
pub use signatures::self_signed_certificate;

/// The crate README's code, compiled as a doctest so it cannot drift from
/// the API it shows. Exists only when doctests are built.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// A rustls client configuration builder with macula's crypto provider
/// and TLS 1.3 already fixed. Continue with a verifier and client
/// authentication; the key exchange groups are not the caller's to set.
pub fn client_builder() -> ConfigBuilder<ClientConfig, WantsVerifier> {
    ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(TLS_1_3_ONLY)
        .expect(PROVIDER_SPEAKS_TLS_1_3)
}

/// A rustls server configuration builder with macula's crypto provider
/// and TLS 1.3 already fixed. Continue with client authentication and a
/// certificate; the key exchange groups are not the caller's to set.
pub fn server_builder() -> ConfigBuilder<ServerConfig, WantsVerifier> {
    ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(TLS_1_3_ONLY)
        .expect(PROVIDER_SPEAKS_TLS_1_3)
}

/// TLS 1.3 only. QUIC requires it, and both hybrids refuse TLS 1.2 on
/// their own (`macula-pqc-kx`'s `usable_for_tls13_only`), which is what
/// actually enforces it and is tested there. Stated here as well so that a
/// consumer building rustls with its `tls12` feature, as `macula_quic`
/// does, does not put TLS 1.2 in our ClientHello.
/// The QUIC Initial packet suite, AES-128-GCM with SHA-256, for a QUIC stack built on these builders.
///
/// RFC 9001 protects every QUIC version-1 Initial packet with AES-128-GCM, whatever suite the TLS handshake
/// negotiates. quinn looks for that suite in the provider's own `cipher_suites` by default, and the provider here
/// offers AES-256-GCM alone (macula issue #39), so a quinn consumer passes this suite explicitly:
/// `QuicClientConfig::with_initial(Arc::new(config), macula_pqc::quic_initial_suite())`, and the same for
/// `QuicServerConfig`. `try_from` on a config from these builders fails with `NoInitialCipherSuite`.
pub fn quic_initial_suite() -> rustls::quic::Suite {
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite")
        .quic_suite()
        .expect("TLS13_AES_128_GCM_SHA256 carries QUIC header protection, as RFC 9001 requires")
}

const TLS_1_3_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// The only way this can fail is a provider with no TLS 1.3 cipher suite,
/// and ours is `aws-lc-rs`'s default. Every test below builds through it.
const PROVIDER_SPEAKS_TLS_1_3: &str = "aws-lc-rs's default provider has TLS 1.3 cipher suites";

/// The crypto provider inside both builders. Private: see the crate docs.
///
/// # The key exchange groups
///
/// `[SecP384r1MLKEM1024, SecP256r1MLKEM768]`, in preference order, both
/// from `macula-pqc-kx`: ML-KEM from `macula-mlkem`, ECDH from `aws-lc-rs`.
///
/// - **`SecP384r1MLKEM1024` leads** because it is the group macula's
///   `pq_hybrid` profile declares, so two macula peers on this provider
///   negotiate it.
/// - **`SecP256r1MLKEM768` follows**: it is the hybrid on BSI TR-02102-2's
///   list, and the one `macula_quic` led with before it moved to this
///   crate (macula `c91e0214`). A peer still on that list has no
///   `SecP384r1MLKEM1024`, so it and this provider agree on
///   `SecP256r1MLKEM768`, after one HelloRetryRequest when we dial it.
///
/// # The signatures
///
/// ML-DSA-87 alone, from `macula-mldsa`: the provider's signature
/// verification algorithms are ML-DSA-87 for certificates and for TLS 1.3
/// CertificateVerify, and its key loader takes an ML-DSA-87 PKCS#8 key and
/// nothing else (the `signatures` module). So a server built here signs
/// its handshakes with ML-DSA-87, and every verifier built on either
/// configuration, rustls' own or a caller's, refuses a classical
/// signature. `a_classical_signature_cannot_agree_with_us` is the negative
/// control, in both roles.
///
/// Everything else comes from `aws-lc-rs`'s default provider: cipher
/// suites, and randomness for the TLS layer.
///
/// # ⛔ Nothing classical is offered, and three things depend on that
///
/// 1. **Nothing classical is offered.** A peer with no post-quantum group
///    in common fails to connect rather than quietly agreeing on X25519.
///    `nothing_classical_is_offered` asserts it.
/// 2. **The offering is proved real by a negative control**, below: a
///    classical-only peer CANNOT agree with this provider, in either role.
///    It could only agree if the list were not in force.
/// 3. **Erlang deduces the negotiated group from (1) and (2).** `quinn`
///    does not surface the group a QUIC connection negotiated, so
///    `macula_quic_pq_kx_tests` cannot ask for it. It argues instead that
///    a handshake which completes while only post-quantum groups are
///    offered cannot have landed on a classical one.
///
/// ⚠ **ADDING A CLASSICAL FALLBACK GROUP HERE KILLS THAT DEDUCTION.** A
/// completed QUIC handshake would once more be consistent with X25519, and
/// the Erlang test would stop proving anything while staying green. So a
/// fallback obliges a negative control IN ERLANG, against a classical-only
/// peer, which needs a per-endpoint key exchange group option on the NIF.
/// If you are adding the fallback, that is part of the work.
///
fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: vec![
            macula_pqc_kx::SECP384R1MLKEM1024,
            macula_pqc_kx::SECP256R1MLKEM768,
        ],
        // AES-256-GCM with SHA-384 only: the one TLS 1.3 suite on CNSA 2.0's list. Left to the default, the
        // provider also offered AES-128-GCM and ChaCha20 (macula issue #39). QUIC Initial packets stay
        // AES-128-GCM, as RFC 9001 fixes for every QUIC version-1 connection.
        cipher_suites: vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        signature_verification_algorithms: signatures::SIGNATURE_VERIFICATION_ALGORITHMS,
        key_provider: &signatures::KeyLoader,
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

#[cfg(test)]
mod tests {
    //! The negative control lives HERE, next to the list, so the list and
    //! the proof that it is in force cannot drift apart. Our side of every
    //! handshake is built through `client_builder` and `server_builder`,
    //! the only way a consumer can get a configuration from this crate.

    use std::sync::Arc;

    use rcgen::{CertificateParams, KeyPair};
    use rustls::crypto::aws_lc_rs::cipher_suite as aws_suite;
    use rustls::crypto::aws_lc_rs::kx_group as aws;
    use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
    use rustls::pki_types::{
        alg_id, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
        SignatureVerificationAlgorithm,
    };
    use rustls::sign::{CertifiedKey, SingleCertAndKey};
    use rustls::{
        CipherSuite, ClientConfig, ClientConnection, Connection, NamedGroup, RootCertStore,
        ServerConfig, ServerConnection, SignatureScheme,
    };

    use super::{
        client_builder, provider, self_signed_certificate, server_builder, KeyPossessionVerifier,
    };

    /// `SecP384r1MLKEM1024`. rustls 0.23.43 has no variant for it.
    const SECP384R1MLKEM1024: NamedGroup = NamedGroup::Unknown(0x11ED);

    /// The groups whose shared secret a quantum computer cannot recover
    /// from the wire: ML-KEM and the hybrids that carry it. Named rather
    /// than derived from code points, so a classical group numbered near
    /// the ML-KEM block cannot count as post-quantum by accident.
    fn is_post_quantum(group: NamedGroup) -> bool {
        group == SECP384R1MLKEM1024
            || matches!(
                group,
                NamedGroup::MLKEM512
                    | NamedGroup::MLKEM768
                    | NamedGroup::MLKEM1024
                    | NamedGroup::secp256r1MLKEM768
                    | NamedGroup::X25519MLKEM768
            )
    }

    /// What each builder a consumer can obtain actually carries.
    fn locked_lists() -> [(&'static str, Vec<&'static dyn SupportedKxGroup>); 2] {
        [
            (
                "client_builder",
                client_builder().crypto_provider().kx_groups.clone(),
            ),
            (
                "server_builder",
                server_builder().crypto_provider().kx_groups.clone(),
            ),
        ]
    }

    /// Exactly our two hybrids, in this order, and they are OUR objects,
    /// in both builders. `aws-lc-rs` ships a `SECP256R1MLKEM768` with the
    /// same name, the same lengths and the same behaviour on the wire, so
    /// only identity tells ours from theirs.
    #[test]
    fn both_builders_carry_our_two_hybrids_in_order_and_nothing_else() {
        for (builder, groups) in locked_lists() {
            let names: Vec<NamedGroup> = groups.iter().map(|g| g.name()).collect();
            assert_eq!(groups.len(), 2, "{builder}: {names:?}");
            assert!(
                std::ptr::addr_eq(groups[0], macula_pqc_kx::SECP384R1MLKEM1024),
                "{builder}: first group is not macula-pqc-kx's SecP384r1MLKEM1024"
            );
            assert!(
                std::ptr::addr_eq(groups[1], macula_pqc_kx::SECP256R1MLKEM768),
                "{builder}: second group is not macula-pqc-kx's SecP256r1MLKEM768"
            );
            assert!(
                !std::ptr::addr_eq(groups[1], aws::SECP256R1MLKEM768),
                "{builder}: second group is aws-lc-rs's, which runs aws-lc-rs's ML-KEM"
            );
        }
    }

    /// Every group in one builder's locked list is post-quantum.
    fn assert_only_post_quantum(builder: &str, groups: &[&dyn SupportedKxGroup]) {
        for group in groups {
            assert!(
                is_post_quantum(group.name()),
                "{builder}: {:?} is offered and is classical",
                group.name()
            );
        }
    }

    /// The property itself, independent of the exact list, so a later
    /// change to the list still has to keep it.
    #[test]
    fn nothing_classical_is_offered() {
        for (builder, groups) in locked_lists() {
            assert_only_post_quantum(builder, &groups);
        }
    }

    /// The certificates and handshake signatures both builders accept: ML-DSA-87, and nothing classical. Every
    /// verifier built on either configuration checks signatures with these, so a peer that signs classically fails.
    #[test]
    fn both_builders_verify_ml_dsa_87_and_nothing_else() {
        for (builder, provider) in [
            ("client_builder", client_builder().crypto_provider().clone()),
            ("server_builder", server_builder().crypto_provider().clone()),
        ] {
            assert_eq!(
                provider
                    .signature_verification_algorithms
                    .supported_schemes(),
                vec![rustls::SignatureScheme::ML_DSA_87],
                "{builder}"
            );
        }
    }

    /// Two macula peers agree on the group the list leads with.
    #[test]
    fn two_peers_on_these_builders_negotiate_secp384r1mlkem1024() {
        let id = Identity::new();
        let agreed = handshake(our_client(&id), our_server(&id));
        assert_eq!(agreed, Ok(SECP384R1MLKEM1024));
    }

    /// `macula_quic`'s list as it stands at macula `c91e0214`, before it
    /// moves to this crate: all four on `aws-lc-rs`. A peer on it has no
    /// `SecP384r1MLKEM1024`, so the two agree on `SecP256r1MLKEM768`, ours
    /// against `aws-lc-rs`'s in a full TLS handshake, in both roles. This
    /// is also the positive twin of the negative control below: the same
    /// harness, a peer with a group in common, a handshake that completes.
    fn macula_quic_list_today() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![
                aws::SECP256R1MLKEM768,
                aws::X25519MLKEM768,
                aws::MLKEM1024,
                aws::MLKEM768,
            ],
            ..provider()
        }
    }

    #[test]
    fn a_peer_on_macula_quics_current_list_negotiates_secp256r1mlkem768() {
        let id = Identity::new();
        let as_client = handshake(our_client(&id), peer_server(macula_quic_list_today(), &id));
        let as_server = handshake(peer_client(macula_quic_list_today(), &id), our_server(&id));
        assert_eq!(as_client, Ok(NamedGroup::secp256r1MLKEM768), "we dial them");
        assert_eq!(as_server, Ok(NamedGroup::secp256r1MLKEM768), "they dial us");
    }

    /// ⛔ THE NEGATIVE CONTROL. The tests above show post-quantum groups
    /// being negotiated. They do not show the list doing any work: if
    /// `kx_groups` were ignored and a default applied, handshakes would
    /// still come up. So a peer offering ONLY classical groups must FAIL
    /// to agree with us, in both roles. It can only fail if our list is
    /// genuinely in force.
    #[test]
    fn a_classical_only_peer_cannot_agree_with_us() {
        let classical = || CryptoProvider {
            kx_groups: vec![aws::X25519, aws::SECP256R1, aws::SECP384R1],
            ..provider()
        };
        let id = Identity::new();
        let as_client = handshake(our_client(&id), peer_server(classical(), &id));
        let as_server = handshake(peer_client(classical(), &id), our_server(&id));
        assert!(
            as_client.is_err(),
            "a classical-only server agreed with us: {as_client:?}"
        );
        assert!(
            as_server.is_err(),
            "a classical-only client agreed with us: {as_server:?}"
        );
    }

    /// The one TLS 1.3 cipher suite both builders offer: AES-256-GCM with SHA-384, the only one on CNSA 2.0's
    /// list. The provider used to take `cipher_suites` from `aws-lc-rs`'s default, which adds AES-128-GCM and
    /// ChaCha20 (macula issue #39). QUIC still protects its Initial packets with AES-128-GCM, as RFC 9001 fixes;
    /// that is the transport's rule, not this list.
    #[test]
    fn both_builders_offer_only_tls13_aes_256_gcm_sha384() {
        for (builder, suites) in [
            (
                "client_builder",
                client_builder().crypto_provider().cipher_suites.clone(),
            ),
            (
                "server_builder",
                server_builder().crypto_provider().cipher_suites.clone(),
            ),
        ] {
            let names: Vec<CipherSuite> = suites.iter().map(|s| s.suite()).collect();
            assert_eq!(
                names,
                vec![CipherSuite::TLS13_AES_256_GCM_SHA384],
                "{builder}"
            );
        }
    }

    /// ⛔ THE CIPHER SUITE NEGATIVE CONTROL, both roles. A peer with our groups and our signatures that offers
    /// only AES-128-GCM and ChaCha20 must fail to agree with us. It can only fail if our one-suite list is in
    /// force: with the default list it would agree on AES-128-GCM.
    #[test]
    fn a_peer_without_aes_256_gcm_cannot_agree_with_us() {
        let narrower = || CryptoProvider {
            cipher_suites: vec![
                aws_suite::TLS13_AES_128_GCM_SHA256,
                aws_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ],
            ..provider()
        };
        let id = Identity::new();
        let as_client = handshake(our_client(&id), peer_server(narrower(), &id));
        let as_server = handshake(peer_client(narrower(), &id), our_server(&id));
        assert!(
            as_client.is_err(),
            "a server without AES-256-GCM agreed with us: {as_client:?}"
        );
        assert!(
            as_server.is_err(),
            "a client without AES-256-GCM agreed with us: {as_server:?}"
        );
    }

    /// The TLS signature schemes a classical peer verifies.
    const CLASSICAL_SCHEMES: &[SignatureScheme] = &[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
    ];

    /// rustls' aws-lc-rs default verification list with every ML-DSA algorithm removed, from the handshake
    /// schemes and from the certificate algorithms alike: a peer that verifies classically by construction.
    fn classical_verification() -> WebPkiSupportedAlgorithms {
        let ml_dsa = [alg_id::ML_DSA_44, alg_id::ML_DSA_65, alg_id::ML_DSA_87];
        let default =
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        let all: Vec<&'static dyn SignatureVerificationAlgorithm> = default
            .all
            .iter()
            .copied()
            .filter(|a| !ml_dsa.contains(&a.public_key_alg_id()))
            .collect();
        let mapping: Vec<(
            SignatureScheme,
            &'static [&'static dyn SignatureVerificationAlgorithm],
        )> = default
            .mapping
            .iter()
            .copied()
            .filter(|(scheme, _)| CLASSICAL_SCHEMES.contains(scheme))
            .collect();
        WebPkiSupportedAlgorithms {
            all: Box::leak(all.into_boxed_slice()),
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    }

    /// ⛔ THE SIGNATURE NEGATIVE CONTROL, both roles. A server that signs classically cannot agree with our client,
    /// and a client that verifies only classical signatures cannot agree with our server. Each peer keeps our key
    /// exchange groups, so the signature is the only thing that can have failed.
    #[test]
    fn a_classical_signature_cannot_agree_with_us() {
        let classical_signatures = || CryptoProvider {
            signature_verification_algorithms: classical_verification(),
            key_provider: rustls::crypto::aws_lc_rs::default_provider().key_provider,
            ..provider()
        };
        // The premise, checked rather than inherited: since rustls 0.23.46 the aws-lc-rs default also verifies
        // ML-DSA, so the peer's list is that default with ML-DSA cut out, and it must hold nothing else.
        let schemes = classical_signatures()
            .signature_verification_algorithms
            .supported_schemes();
        assert!(!schemes.is_empty());
        assert!(
            schemes.iter().all(|s| CLASSICAL_SCHEMES.contains(s)),
            "the classical peer verifies something not classical: {schemes:?}"
        );
        let classical = Identity::classical();
        let ours = Identity::new();
        let we_dial = handshake(
            our_client(&classical),
            peer_server(classical_signatures(), &classical),
        );
        let they_dial = handshake(
            peer_client(classical_signatures(), &ours),
            our_server(&ours),
        );
        assert!(
            we_dial.is_err(),
            "a server signing classically agreed with us: {we_dial:?}"
        );
        assert!(
            they_dial.is_err(),
            "a client verifying classically agreed with us: {they_dial:?}"
        );
        // The positive twin: the same classical peers agree with each other, so the harness can complete a
        // handshake with them at all.
        let classical_pair = handshake(
            peer_client(classical_signatures(), &classical),
            peer_server(classical_signatures(), &classical),
        );
        assert_eq!(classical_pair, Ok(SECP384R1MLKEM1024));
    }

    // -----------------------------------------------------------------
    // KeyPossessionVerifier: macula's one client verification mode
    // -----------------------------------------------------------------

    /// A client on the builder with no roots at all, trusting whatever ML-DSA-87 key the server shows it can sign
    /// with, as a macula client dials a station.
    fn possession_client() -> ClientConfig {
        client_builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(KeyPossessionVerifier::new()))
            .with_no_client_auth()
    }

    /// A server on the builder presenting `chain` and signing its handshake with `key`, whatever the two are.
    /// `with_single_cert` would refuse a key that is not the certificate's; a resolver does not check, so a test can
    /// build the server that the verifier must refuse.
    fn presenting(
        chain: Vec<CertificateDer<'static>>,
        key: &PrivateKeyDer<'static>,
    ) -> ServerConfig {
        let signing_key = provider()
            .key_provider
            .load_private_key(key.clone_key())
            .unwrap();
        server_builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(CertifiedKey::new(
                chain,
                signing_key,
            ))))
    }

    /// With no root store, a server holding the key in its ML-DSA-87 certificate is accepted.
    #[test]
    fn key_possession_accepts_a_server_holding_its_certificates_key() {
        let id = Identity::new();
        assert_eq!(
            handshake(possession_client(), our_server(&id)),
            Ok(SECP384R1MLKEM1024)
        );
    }

    /// ⛔ THE VERIFIER'S NEGATIVE CONTROL. A server presenting one ML-DSA-87 certificate and signing its handshake
    /// with another ML-DSA-87 key must fail: that is the one thing the verifier proves, so a verifier that let the
    /// handshake signature through unchecked would pass every other test here. The positive twin, the same harness
    /// with the certificate's own key, completes.
    #[test]
    fn key_possession_refuses_a_server_that_cannot_sign_for_its_certificate() {
        let (ours, other) = (Identity::new(), Identity::new());
        let wrong_key = handshake(
            possession_client(),
            presenting(ours.chain.clone(), &other.key),
        );
        assert!(
            wrong_key.is_err(),
            "a server signing with another key was accepted: {wrong_key:?}"
        );
        assert_eq!(
            handshake(
                possession_client(),
                presenting(ours.chain.clone(), &ours.key)
            ),
            Ok(SECP384R1MLKEM1024)
        );
    }

    /// A station presents its one self-signed certificate. A chain is refused, not ignored.
    #[test]
    fn key_possession_refuses_a_chain() {
        let (ours, other) = (Identity::new(), Identity::new());
        let chain = vec![ours.chain[0].clone(), other.chain[0].clone()];
        let agreed = handshake(possession_client(), presenting(chain, &ours.key));
        assert!(
            agreed.is_err(),
            "a chain of two certificates was accepted: {agreed:?}"
        );
    }

    /// A certificate whose key is not ML-DSA-87 is refused, even from a server that signs its handshake with
    /// ML-DSA-87.
    #[test]
    fn key_possession_refuses_a_classical_certificate() {
        let (classical, ours) = (Identity::classical(), Identity::new());
        let agreed = handshake(
            possession_client(),
            presenting(classical.chain.clone(), &ours.key),
        );
        assert!(
            agreed.is_err(),
            "an ECDSA certificate was accepted: {agreed:?}"
        );
    }

    // -----------------------------------------------------------------
    // A real TLS 1.3 handshake, in memory
    // -----------------------------------------------------------------

    /// A self-signed server certificate the client trusts as its root, so the client verifies the certificate's
    /// signature for real rather than skipping verification.
    struct Identity {
        roots: RootCertStore,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    }

    impl Identity {
        /// An ML-DSA-87 identity from a fresh seed, as a macula node's TLS key is.
        fn new() -> Identity {
            let (_public, seed) = macula_mldsa::key_gen_seed(macula_mldsa::ML_DSA_87).unwrap();
            let (certificate, key) =
                self_signed_certificate(&seed, vec!["localhost".to_string()]).unwrap();
            Identity::of(certificate, key.into())
        }

        /// A classical identity, ECDSA P-256, for the negative control.
        fn classical() -> Identity {
            let key = KeyPair::generate().unwrap();
            let certificate = CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            Identity::of(
                certificate.der().clone(),
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
        }

        fn of(certificate: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Identity {
            let mut roots = RootCertStore::empty();
            roots.add(certificate.clone()).unwrap();
            Identity {
                roots,
                chain: vec![certificate],
                key,
            }
        }
    }

    fn our_server(id: &Identity) -> ServerConfig {
        server_builder()
            .with_no_client_auth()
            .with_single_cert(id.chain.clone(), id.key.clone_key())
            .unwrap()
    }

    fn our_client(id: &Identity) -> ClientConfig {
        client_builder()
            .with_root_certificates(id.roots.clone())
            .with_no_client_auth()
    }

    /// A peer on some other provider: the lists we must interoperate with
    /// or refuse.
    fn peer_server(provider: CryptoProvider, id: &Identity) -> ServerConfig {
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(id.chain.clone(), id.key.clone_key())
            .unwrap()
    }

    fn peer_client(provider: CryptoProvider, id: &Identity) -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(id.roots.clone())
            .with_no_client_auth()
    }

    /// One handshake; the group both sides agreed on, or why they did not.
    /// A failure to agree is a result here, not an error: it is what the
    /// negative control asserts. Both sides must report the same group.
    fn handshake(client_cfg: ClientConfig, server_cfg: ServerConfig) -> Result<NamedGroup, String> {
        let name = ServerName::try_from("localhost").unwrap();
        let mut client = Connection::Client(
            ClientConnection::new(Arc::new(client_cfg), name).map_err(|e| e.to_string())?,
        );
        let mut server = Connection::Server(
            ServerConnection::new(Arc::new(server_cfg)).map_err(|e| e.to_string())?,
        );
        // Far more flights than TLS 1.3 needs, including a HelloRetryRequest;
        // bounds a handshake that stops making progress.
        pump_until_settled(&mut client, &mut server)?;
        if client.is_handshaking() || server.is_handshaking() {
            return Err("handshake never completed".to_string());
        }
        let agreed = |c: &Connection| c.negotiated_key_exchange_group().map(|g| g.name());
        match (agreed(&client), agreed(&server)) {
            (Some(c), Some(s)) if c == s => Ok(c),
            other => Err(format!("the two sides disagree on the group: {other:?}")),
        }
    }

    /// Move the handshake along until neither side has anything left to
    /// say, or the flight budget is spent.
    fn pump_until_settled(client: &mut Connection, server: &mut Connection) -> Result<(), String> {
        let mut flights = 0;
        let mut moved = 1;
        while flights < 20 && (moved > 0 || client.is_handshaking() || server.is_handshaking()) {
            moved = pump(client, server)? + pump(server, client)?;
            flights += 1;
        }
        Ok(())
    }

    /// Moves what `from` wants to send into `to`; returns the bytes moved.
    fn pump(from: &mut Connection, to: &mut Connection) -> Result<usize, String> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut cursor = std::io::Cursor::new(&buf[..]);
        while (cursor.position() as usize) < buf.len() {
            to.read_tls(&mut cursor).map_err(|e| e.to_string())?;
            to.process_new_packets().map_err(|e| e.to_string())?;
        }
        Ok(buf.len())
    }
}
