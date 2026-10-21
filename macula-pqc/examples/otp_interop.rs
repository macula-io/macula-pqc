//! Interop between `macula-pqc`'s TLS configurations and OTP's own `ssl`: the key exchange and the signatures.
//!
//! Run with `scripts/otp-interop.sh`. Not part of the gate: it needs an OTP installation with ML-KEM and ML-DSA in
//! TLS (28.4 or later), which CI does not have.
//!
//! # Why OTP
//!
//! OTP's `ssl` is the one INDEPENDENT implementation of `SecP384r1MLKEM1024` there is to exchange with: no Rust
//! provider has one, so `macula-pqc-kx`'s own tests can only exchange that group with itself. OTP composes the hybrid
//! in its own Erlang code and takes ML-KEM and ECDH from its `crypto` library. It also signs and verifies TLS 1.3
//! handshakes and certificates with ML-DSA-87 from `crypto`, independently of `macula-mldsa`. So a completed handshake
//! means two independently written implementations agreed on the group, the shares and the secret, and on the
//! ML-DSA-87 signature scheme, its encoding, the certificate's key and the PKCS#8 key it was loaded from.
//!
//! # What each case checks
//!
//! Every certificate on our side is ML-DSA-87, from `macula_pqc::self_signed_certificate`, and OTP offers exactly ONE
//! group and only `mldsa87` per case, so a completed handshake leaves nothing else to have agreed on. The rustls side
//! reports the group it negotiated as well. A `ping`/`pong` then crosses the connection, both roles.
//!
//! - **We serve, OTP dials:** `macula-mldsa` signs the handshake, and OTP checks it against our certificate.
//! - **OTP serves, we dial:** OTP signs the handshake with the same key, read from our PKCS#8 encoding of its seed,
//!   and `macula-mldsa` checks it.
//! - **We dial with no roots, OTP serves:** our client trusts the server by `macula_pqc::KeyPossessionVerifier`
//!   alone, as a macula client dials a station, so the only check is OTP's handshake signature under the key in the
//!   certificate it presents.
//! - **OTP checks our certificate's own signature** with `public_key:pkix_verify/2`. A handshake does not check it:
//!   OTP trusts that certificate as a trust anchor, and a trust anchor's own signature is never verified.
//!
//! The negative controls, each against the passing cases' harness with one thing changed:
//!
//! - OTP offering only classical key exchange groups must fail to agree with us, in both roles;
//! - OTP offering only classical signature algorithms must fail to agree with our server;
//! - OTP serving a classical certificate, Ed25519, must fail to agree with our client.
//!
//! Exit codes: 0 every case as expected; 1 an interop case failed; 2 a negative control failed; 3 this OTP cannot run
//! the check.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
    StreamOwned,
};

const TIMEOUT: Duration = Duration::from_secs(20);

/// `(OTP's name for the group, what rustls must report)`.
const HYBRIDS: [(&str, NamedGroup); 2] = [
    ("secp384r1mlkem1024", NamedGroup::Unknown(0x11ED)),
    ("secp256r1mlkem768", NamedGroup::secp256r1MLKEM768),
];
const CLASSICAL_ONLY: &str = "x25519,secp256r1,secp384r1";
const MLDSA87: &str = "mldsa87";
const CLASSICAL_SIGNATURES: &str = "eddsa_ed25519,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha256";

fn main() {
    let otp_bin = PathBuf::from(std::env::var("OTP_BIN").expect("OTP_BIN: OTP's bin directory"));
    let (release, crypto_lib) = otp_facts(&otp_bin);
    println!("OTP {release}, crypto library {crypto_lib}, against macula-pqc\n");

    let dir = std::env::temp_dir().join(format!("macula-pqc-otp-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = Identity::write(&dir);
    let peer = Peer {
        escript: otp_bin.join("escript"),
        script: PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/otp_peer.escript"
        )),
        dir: dir.clone(),
    };

    let mut interop_failed = hybrids_interop(&peer, &identity);
    interop_failed |= !key_possession(&peer);
    interop_failed |= !our_certificate(&peer);
    let control_failed = classical_controls(&peer, &identity);

    std::fs::remove_dir_all(&dir).unwrap();
    println!();
    if control_failed {
        println!("NEGATIVE CONTROL FAILED: a classical OTP peer agreed with macula-pqc.");
        std::process::exit(2);
    }
    if interop_failed {
        println!("INTEROP FAILED in at least one case.");
        std::process::exit(1);
    }
    println!(
        "macula-pqc and OTP's ssl agree on both hybrids and on ML-DSA-87 in both roles; classical key exchange and \
         classical signatures refused."
    );
}

/// Both hybrids, both roles: OTP dialling and us serving, then the other way
/// round. `true` when every case did what it had to.
fn hybrids_interop(peer: &Peer, identity: &Identity) -> bool {
    let mut failed = false;
    for (otp_name, expected) in HYBRIDS {
        let cases = [
            (
                "OTP dials, we serve",
                we_serve(peer, identity, otp_name, MLDSA87),
            ),
            (
                "we dial, OTP serves",
                we_dial(peer, identity.client(), otp_name, "ours"),
            ),
        ];
        for (role, outcome) in cases {
            failed |= !report_hybrid(role, otp_name, expected, outcome);
        }
    }
    failed
}

/// One hybrid case's line, and the error under it when it failed.
fn report_hybrid(
    role: &str,
    otp_name: &str,
    expected: NamedGroup,
    outcome: Result<NamedGroup, String>,
) -> bool {
    let pass = outcome == Ok(expected);
    println!(
        "{role:<22} OTP offers {otp_name:<26} {:<34} {}",
        describe(&outcome),
        if pass { "PASS" } else { "FAIL" }
    );
    report_detail(&outcome);
    pass
}

/// The error under a failed line, or nothing.
fn report_detail(outcome: &Result<NamedGroup, String>) {
    if let Err(e) = outcome {
        println!("{:<22} {e}", "");
    }
}

/// No roots at all: key possession alone has to carry the handshake.
fn key_possession(peer: &Peer) -> bool {
    let (otp_name, expected) = HYBRIDS[0];
    let possession = we_dial(peer, Identity::possession_client(), otp_name, "ours");
    let pass = possession == Ok(expected);
    println!(
        "{:<22} {:<37} {:<34} {}",
        "we dial, OTP serves",
        "no roots: key possession alone",
        describe(&possession),
        if pass { "PASS" } else { "FAIL" }
    );
    report_detail(&possession);
    pass
}

/// OTP checks our certificate's own signature.
fn our_certificate(peer: &Peer) -> bool {
    let certificate = peer.run(&["verify_cert"]);
    println!(
        "{:<22} {:<37} {:<34} {}",
        "OTP checks",
        "our certificate's own signature",
        "",
        if certificate.is_ok() { "PASS" } else { "FAIL" }
    );
    report_certificate(&certificate);
    certificate.is_ok()
}

/// The error under a failed certificate check, or nothing.
fn report_certificate(certificate: &Result<(), String>) {
    if let Err(e) = certificate {
        println!("{:<22} {e}", "");
    }
}

/// A classical peer must be refused every way: key exchange, signatures,
/// and an Ed25519 certificate. `true` when one was accepted.
fn classical_controls(peer: &Peer, identity: &Identity) -> bool {
    let cases = [
        (
            "OTP dials, we serve",
            CLASSICAL_ONLY,
            we_serve(peer, identity, CLASSICAL_ONLY, MLDSA87),
        ),
        (
            "we dial, OTP serves",
            CLASSICAL_ONLY,
            we_dial(peer, identity.client(), CLASSICAL_ONLY, "ours"),
        ),
        (
            "OTP dials, we serve",
            "classical signatures only",
            we_serve(peer, identity, HYBRIDS[0].0, CLASSICAL_SIGNATURES),
        ),
        (
            "we dial, OTP serves",
            "an Ed25519 certificate",
            we_dial(peer, identity.client(), HYBRIDS[0].0, "classical"),
        ),
    ];
    let mut failed = false;
    for (role, offer, outcome) in cases {
        failed |= !report_control(role, offer, outcome);
    }
    failed
}

/// One negative control's line: it must be refused. `true` when it was.
fn report_control(role: &str, offer: &str, outcome: Result<NamedGroup, String>) -> bool {
    let pass = outcome.is_err();
    println!(
        "{role:<22} OTP offers {offer:<26} {:<34} {}",
        describe(&outcome),
        if pass {
            "PASS (refused, as required)"
        } else {
            "FAIL: a classical peer agreed"
        }
    );
    report_detail(&outcome);
    pass
}

fn describe(outcome: &Result<NamedGroup, String>) -> String {
    match outcome {
        Ok(NamedGroup::Unknown(0x11ED)) => "agreed on SecP384r1MLKEM1024".to_string(),
        Ok(group) => format!("agreed on {group:?}"),
        Err(_) => "no agreement".to_string(),
    }
}

/// The OTP release and the library its `crypto` is built on, checked for
/// the groups this needs before anything runs.
fn otp_facts(otp_bin: &Path) -> (String, String) {
    let out = Command::new(otp_bin.join("erl"))
        .args([
            "-noshell",
            "-eval",
            r#"
            {ok, _} = application:ensure_all_started(ssl),
            Needed = [secp384r1mlkem1024, secp256r1mlkem768],
            Missing = (Needed -- ssl:groups(default)) ++
                      ([mldsa87] -- ssl:signature_algs(all, 'tlsv1.3')),
            {ok, V} = file:read_file(filename:join([code:root_dir(), "releases",
                                     erlang:system_info(otp_release), "OTP_VERSION"])),
            [{Lib, _, Name}] = crypto:info_lib(),
            io:format("~s~n~s ~s~n~p~n", [string:trim(V), Lib, Name, Missing]),
            halt()."#,
        ])
        .output()
        .expect("run OTP's erl");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    if !out.status.success() || lines.len() < 3 {
        eprintln!(
            "cannot query OTP at {}:\n{text}{}",
            otp_bin.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        std::process::exit(3);
    }
    if lines[2] != "[]" {
        eprintln!(
            "OTP {} lacks groups or signature algorithms this check needs: {}",
            lines[0], lines[2]
        );
        std::process::exit(3);
    }
    (lines[0].to_string(), lines[1].to_string())
}

// ---------------------------------------------------------------------
// The two roles
// ---------------------------------------------------------------------

struct Peer {
    escript: PathBuf,
    script: PathBuf,
    dir: PathBuf,
}

impl Peer {
    /// One OTP command that prints only its verdict.
    fn run(&self, args: &[&str]) -> Result<(), String> {
        let mut otp = self.spawn(args);
        finish(&mut otp)
    }

    fn spawn(&self, args: &[&str]) -> Child {
        Command::new(&self.escript)
            .arg(&self.script)
            .args(args)
            .arg(&self.dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start OTP's escript")
    }
}

/// OTP dials, `macula-pqc` serves. The group is what rustls reports; the
/// result is `Ok` only if OTP also completed the ping/pong.
fn we_serve(
    peer: &Peer,
    id: &Identity,
    otp_groups: &str,
    otp_signatures: &str,
) -> Result<NamedGroup, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().unwrap().port().to_string();
    let mut otp = peer.spawn(&["dial", &port, otp_groups, otp_signatures]);
    let ours = (|| {
        let tcp = accept_within(&listener, TIMEOUT)?;
        tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
        let conn = ServerConnection::new(Arc::new(id.server())).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        let mut ping = [0u8; 4];
        tls.read_exact(&mut ping).map_err(|e| e.to_string())?;
        if &ping != b"ping" {
            return Err(format!("read {ping:?}, not ping"));
        }
        tls.write_all(b"pong").map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        agreed_group(&tls.conn)
    })();
    both(ours, finish(&mut otp))
}

/// `macula-pqc` dials, OTP serves the identity named `otp_identity`.
fn we_dial(
    peer: &Peer,
    client: ClientConfig,
    otp_groups: &str,
    otp_identity: &str,
) -> Result<NamedGroup, String> {
    let mut otp = peer.spawn(&["serve", otp_groups, otp_identity]);
    let ours = (|| {
        let port = first_line_within(&mut otp, TIMEOUT)?
            .strip_prefix("port ")
            .ok_or("OTP did not report its port")?
            .trim()
            .to_string();
        let tcp = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(client), name).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(b"ping").map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        let mut pong = [0u8; 4];
        tls.read_exact(&mut pong).map_err(|e| e.to_string())?;
        if &pong != b"pong" {
            return Err(format!("read {pong:?}, not pong"));
        }
        agreed_group(&tls.conn)
    })();
    both(ours, finish(&mut otp))
}

/// `Ok` only if both sides succeeded; otherwise every side's reason.
fn both(
    ours: Result<NamedGroup, String>,
    theirs: Result<(), String>,
) -> Result<NamedGroup, String> {
    match (ours, theirs) {
        (Ok(group), Ok(())) => Ok(group),
        (Ok(_), Err(t)) => Err(t),
        (Err(o), Ok(())) => Err(o),
        (Err(o), Err(t)) => Err(format!("{o} | {t}")),
    }
}

fn agreed_group(conn: &rustls::CommonState) -> Result<NamedGroup, String> {
    conn.negotiated_key_exchange_group()
        .map(|g| g.name())
        .ok_or_else(|| "no group negotiated".to_string())
}

fn accept_within(listener: &TcpListener, limit: Duration) -> Result<TcpStream, String> {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + limit;
    loop {
        match listener.accept() {
            Ok((tcp, _)) => {
                tcp.set_nonblocking(false).unwrap();
                return Ok(tcp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(format!("OTP never connected: {e}")),
        }
    }
}

/// The first line OTP prints. Read on a thread so a silent peer cannot
/// hang the check.
fn first_line_within(otp: &mut Child, limit: Duration) -> Result<String, String> {
    let stdout = otp.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        let _ = tx.send((line, reader));
    });
    let (line, reader) = rx
        .recv_timeout(limit)
        .map_err(|_| "OTP printed nothing".to_string())?;
    // Hand the rest of stdout back, so `finish` can read OTP's verdict.
    otp.stdout = Some(reader.into_inner());
    Ok(line)
}

/// Waits for OTP's verdict: `ok`, or its error.
fn finish(otp: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = otp.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = otp.kill();
            return Err("OTP did not finish".to_string());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = String::new();
    if let Some(mut stdout) = otp.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let verdict = out.lines().last().unwrap_or("").to_string();
    match status.success() && verdict == "ok" {
        true => Ok(()),
        false => Err(format!("OTP: {verdict}")),
    }
}

// ---------------------------------------------------------------------
// The identities, written for OTP and held for rustls
// ---------------------------------------------------------------------

/// Ours: a self-signed ML-DSA-87 certificate and its PKCS#8 key from a fresh seed, as a macula station holds its TLS
/// key, written as ours.der and ours.key.der. And a classical one, Ed25519, self-signed, as classical.der and
/// classical.key.der, for the control where OTP serves a classical certificate. Our client trusts both
/// certificates, so what refuses the classical one is its signature, not an unknown issuer.
struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    classical: CertificateDer<'static>,
}

impl Identity {
    fn write(dir: &Path) -> Identity {
        let (_public, seed) = macula_mldsa::key_gen_seed(macula_mldsa::ML_DSA_87).unwrap();
        let (certificate, key) =
            macula_pqc::self_signed_certificate(&seed, vec!["localhost".to_string()]).unwrap();
        std::fs::write(dir.join("ours.der"), &certificate).unwrap();
        std::fs::write(dir.join("ours.key.der"), key.secret_pkcs8_der()).unwrap();

        let classical_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name = common_name("localhost");
        let classical = params.self_signed(&classical_key).unwrap();
        std::fs::write(dir.join("classical.der"), classical.der()).unwrap();
        std::fs::write(dir.join("classical.key.der"), classical_key.serialize_der()).unwrap();
        Identity {
            certificate,
            key: key.into(),
            classical: classical.der().clone(),
        }
    }

    fn server(&self) -> ServerConfig {
        macula_pqc::server_builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.certificate.clone()], self.key.clone_key())
            .unwrap()
    }

    /// A client with no roots, as a macula client dials a station: it trusts whatever ML-DSA-87 key the server
    /// shows it can sign with (`macula_pqc::KeyPossessionVerifier`).
    fn possession_client() -> ClientConfig {
        macula_pqc::client_builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(macula_pqc::KeyPossessionVerifier::new()))
            .with_no_client_auth()
    }

    fn client(&self) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        roots.add(self.classical.clone()).unwrap();
        macula_pqc::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
}

fn common_name(name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}
