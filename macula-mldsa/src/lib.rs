//! ML-DSA (FIPS 204), implemented here rather than depended on.
//!
//! **Built on `macula-keccak`, deliberately.** FIPS 204 is built on SHAKE128
//! and SHAKE256, so implementing ML-DSA while taking Keccak from a third
//! party would relocate the dependency rather than remove it.
//!
//! ⚠ **ML-DSA is not special here, and this crate does not pretend it is.**
//! FIPS 204 has several good implementations, OTP's `crypto` and `aws-lc-rs`
//! among them. This one is written from scratch and verified byte-exact
//! against NIST's own ACVP vectors: a claim about independence and
//! assurance, not about being first or better.
//!
//! [`key_gen`], [`sign`] and [`verify`] are FIPS 204's Algorithms 1 to 3,
//! at ML-DSA-44, -65 and -87. Key generation and signing draw their
//! randomness from the OS; a private key is used either expanded or as its
//! 32-byte seed ([`PrivateKey`]), and [`key_gen_seed`] generates one kept
//! as its seed. [`public_key`] derives a public key from either form.
//!
//! Signing is timed (see `examples/signing_timing.rs`), the heap is
//! scanned for secrets after every operation (`tests/heap_residue.rs`),
//! and [`key_gen`] and [`sign`] are tested to draw from the OS.

//!
//! # Scope: pure ML-DSA
//!
//! FIPS 204 defines two signature schemes: ML-DSA, which signs the message
//! itself, and HashML-DSA (section 5.4), which signs a pre-computed hash of
//! it. **This crate implements ML-DSA only.** TLS 1.3 and macula's identity
//! signatures both use pure ML-DSA, and HashML-DSA would bring SHA-2, which
//! this workspace deliberately does not own. When the tests run NIST's
//! vectors, the HashML-DSA ones are excluded by count, beside that reason.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// The seeded algorithms and the arithmetic are public only with the
// `internal` feature, which is for testing: see `internal`'s docs.
#[cfg(feature = "internal")]
pub mod encode;
#[cfg(not(feature = "internal"))]
mod encode;
#[cfg(feature = "internal")]
pub mod internal;
#[cfg(not(feature = "internal"))]
mod internal;
#[cfg(feature = "internal")]
pub mod poly;
#[cfg(not(feature = "internal"))]
mod poly;
#[cfg(feature = "internal")]
pub mod sample;
#[cfg(not(feature = "internal"))]
mod sample;

/// The wrapper every secret output comes in: it wipes its contents when
/// dropped. Re-exported so a caller can name the type.
pub use zeroize::Zeroizing;

/// Why an operation refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The OS could not supply randomness. FIPS 204 Algorithm 1 returns an
    /// error here rather than build a key from a seed that was not drawn.
    RandomnessUnavailable,
    /// A context string was longer than 255 bytes, FIPS 204 Algorithms 2
    /// and 3.
    ContextTooLong,
    /// An expanded private key was not the length its parameter set
    /// requires.
    WrongLength,
    /// An expanded private key's parts disagree: its `t0` or its hash of
    /// the public key `tr` is not what its `rho`, `s1` and `s2` determine.
    InconsistentPrivateKey,
}

/// The public key of a private key, in either form: from a seed by FIPS
/// 204 key generation, from an expanded key by recomputing `t` from its
/// `rho`, `s1` and `s2`.
///
/// An expanded key is checked against itself on the way: its stored `t0`
/// and `tr = H(pk)` must be what its other parts determine, or it is
/// refused with [`Error::InconsistentPrivateKey`]. Comparing the result
/// with a stored public key is then the caller's load check.
pub fn public_key(p: ParameterSet, sk: PrivateKey) -> Result<Vec<u8>, Error> {
    match sk {
        PrivateKey::Seed(seed) => Ok(internal::key_gen(p, seed).0),
        PrivateKey::Expanded(bytes) => internal::public_key_of_expanded(p, bytes),
    }
}

/// A private key in either of the forms FIPS 204 allows.
#[derive(Clone, Copy)]
pub enum PrivateKey<'a> {
    /// The encoded private key [`key_gen`] returns, of
    /// [`ParameterSet::private_key_len`] bytes.
    Expanded(&'a [u8]),
    /// The 32-byte seed `xi` it was generated from, which FIPS 204 section
    /// 3.6.3 allows a key to be stored as. It is expanded for each
    /// signature, and the expansion wiped.
    Seed(&'a [u8; 32]),
}

/// FIPS 204 Algorithm 2, `ML-DSA.Sign`, hedged: the signing randomness
/// `rnd` is drawn from the OS for every signature, so signing one message
/// twice gives two different valid signatures.
///
/// `M'` is `0 || |ctx| || ctx || message`, absorbed in pieces rather than
/// built. Errors: a context over 255 bytes, an expanded key of the wrong
/// length, or no randomness from the OS.
pub fn sign(
    p: ParameterSet,
    sk: PrivateKey,
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_drawing_from(p, sk, message, context, os_random)
}

/// [`sign`] with its randomness source as a parameter, so the tests can
/// see what is drawn and make the source fail. The context is checked
/// before anything is drawn, in Algorithm 2's order.
fn sign_drawing_from(
    p: ParameterSet,
    sk: PrivateKey,
    message: &[u8],
    context: &[u8],
    mut random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    context_fits(context)?;
    let mut rnd = Zeroizing::new([0u8; 32]);
    random(&mut *rnd)?;
    internal::sign_message(p, sk, message, context, &rnd)
}

/// FIPS 204 Algorithms 2 and 3, lines 1 to 3.
pub(crate) fn context_fits(context: &[u8]) -> Result<(), Error> {
    if context.len() > 255 {
        Err(Error::ContextTooLong)
    } else {
        Ok(())
    }
}

/// FIPS 204 Algorithm 1, `ML-DSA.KeyGen`: the seed `xi` is drawn from the
/// OS.
///
/// Returns `(pk, sk)`. `sk` wipes itself when dropped.
pub fn key_gen(p: ParameterSet) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    key_gen_drawing_from(p, os_random)
}

/// FIPS 204 Algorithm 3, `ML-DSA.Verify`: whether `signature` is a valid
/// signature on `message` under `pk` and the context string `context`.
///
/// `Ok(false)` for any invalid signature, including a public key or
/// signature of the wrong length, as FIPS 204 section 3.6.2 requires, and
/// a malformed hint. `Err` only for a context over 255 bytes, which the
/// standard answers with an error rather than a verdict. `M'` is
/// `0 || |ctx| || ctx || message`, absorbed in pieces rather than built.
pub fn verify(
    p: ParameterSet,
    pk: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool, Error> {
    context_fits(context)?;
    Ok(internal::verify_absorbing(p, pk, signature, |h| {
        h.update(&[0, context.len() as u8]);
        h.update(context);
        h.update(message);
    }))
}

/// FIPS 204 Algorithm 1 with the private key kept as its 32-byte seed
/// `xi`, the form RFC 9964's `AKP` key stores and FIPS 204 section 3.6.3
/// allows: the seed is drawn from the OS and returned with the public key
/// it generates. Sign with [`PrivateKey::Seed`]; the seed wipes itself when
/// dropped.
pub fn key_gen_seed(p: ParameterSet) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    key_gen_seed_drawing_from(p, os_random)
}

/// [`key_gen_seed`] with its randomness source as a parameter, so the tests
/// can see what is drawn and make the source fail.
fn key_gen_seed_drawing_from(
    p: ParameterSet,
    mut random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    let mut xi = Zeroizing::new([0u8; 32]);
    random(&mut *xi)?;
    let (pk, _expanded) = internal::key_gen(p, &xi);
    Ok((pk, xi))
}

/// [`key_gen`] with its randomness source as a parameter, so the tests can
/// see what is drawn and make the source fail.
fn key_gen_drawing_from(
    p: ParameterSet,
    mut random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let mut xi = Zeroizing::new([0u8; 32]);
    random(&mut *xi)?;
    Ok(internal::key_gen(p, &xi))
}

/// The OS CSPRNG, and nothing else.
fn os_random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::RandomnessUnavailable)
}

/// A FIPS 204 parameter set.
///
/// The fields are the specification's own names from its Table 1, so a
/// reader can check them against the standard rather than against this
/// comment. The sizes that follow from them are functions, not fields, so
/// they cannot disagree with the values they come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterSet {
    /// The name the ACVP vectors use, e.g. `"ML-DSA-87"`.
    pub name: &'static str,
    /// `tau`: the number of +/-1 coefficients in the challenge polynomial.
    pub tau: usize,
    /// `lambda`: the collision strength of the commitment hash, in bits.
    pub lambda: usize,
    /// `gamma_1`: the coefficient range of the masking vector `y`.
    pub gamma1: i32,
    /// `gamma_2`: the low-order rounding range.
    pub gamma2: i32,
    /// `k`: the rows of the matrix `A`.
    pub k: usize,
    /// `l`: the columns of the matrix `A`.
    pub l: usize,
    /// `eta`: the coefficient range of the secret vectors `s1` and `s2`.
    pub eta: i32,
    /// `omega`: the maximum number of ones in the hint.
    pub omega: usize,
}

/// ML-DSA-44, security category 2.
pub const ML_DSA_44: ParameterSet = ParameterSet {
    name: "ML-DSA-44",
    tau: 39,
    lambda: 128,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    k: 4,
    l: 4,
    eta: 2,
    omega: 80,
};

/// ML-DSA-65, security category 3.
pub const ML_DSA_65: ParameterSet = ParameterSet {
    name: "ML-DSA-65",
    tau: 49,
    lambda: 192,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    k: 6,
    l: 5,
    eta: 4,
    omega: 55,
};

/// ML-DSA-87, security category 5. The one macula's identities use.
pub const ML_DSA_87: ParameterSet = ParameterSet {
    name: "ML-DSA-87",
    tau: 60,
    lambda: 256,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    k: 8,
    l: 7,
    eta: 2,
    omega: 75,
};

/// The modulus, `q = 2^23 - 2^13 + 1`.
pub const Q: i32 = 8_380_417;

/// `d`: the bits dropped from `t` by Power2Round.
pub const D: usize = 13;

impl ParameterSet {
    /// `beta = tau * eta`.
    pub const fn beta(&self) -> i32 {
        self.tau as i32 * self.eta
    }

    /// A public key: `rho`, then `t1` at 10 bits per coefficient.
    pub const fn public_key_len(&self) -> usize {
        32 + 32 * self.k * 10
    }

    /// A private key: `rho`, `K`, `tr`, then `s1` and `s2` at
    /// `bitlen(2 eta)` bits and `t0` at `d` bits per coefficient.
    pub const fn private_key_len(&self) -> usize {
        32 + 32 + 64 + 32 * ((self.l + self.k) * self.eta_bits() + D * self.k)
    }

    /// `1 + bitlen(gamma1 - 1)`: the bits of each packed coefficient of
    /// `z`, 18 for gamma1 = 2^17 and 20 for gamma1 = 2^19.
    pub(crate) const fn z_bits(&self) -> usize {
        if self.gamma1 == 1 << 17 {
            18
        } else {
            20
        }
    }

    /// `bitlen((q - 1) / (2 gamma2) - 1)`: the bits of each coefficient of
    /// `w1`, 6 for gamma2 = (q - 1) / 88 and 4 for gamma2 = (q - 1) / 32.
    pub(crate) const fn w1_bits(&self) -> usize {
        if self.gamma2 == (Q - 1) / 88 {
            6
        } else {
            4
        }
    }

    /// `bitlen(2 eta)`: the bits of each packed coefficient of `s1` and
    /// `s2`, 3 for eta = 2 and 4 for eta = 4.
    pub(crate) const fn eta_bits(&self) -> usize {
        if self.eta == 2 {
            3
        } else {
            4
        }
    }

    /// A signature: `c~`, then `z` at `1 + bitlen(gamma_1 - 1)` bits per
    /// coefficient, then the hint.
    pub const fn signature_len(&self) -> usize {
        self.lambda / 4 + self.l * 32 * self.z_bits() + self.omega + self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_source_is_an_error_not_a_key() {
        let got = key_gen_drawing_from(ML_DSA_87, |_| Err(Error::RandomnessUnavailable));
        assert_eq!(got.err(), Some(Error::RandomnessUnavailable));
    }

    /// Exactly one 32-byte seed is drawn, and the key is the one
    /// `KeyGen_internal` makes from it: the OS path adds nothing and drops
    /// nothing.
    #[test]
    fn the_key_is_keygen_internal_of_the_drawn_seed() {
        let mut drawn = Vec::new();
        let (pk, sk) = key_gen_drawing_from(ML_DSA_87, |buf| {
            buf.fill(0x5a);
            drawn.push(buf.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(drawn, vec![32]);
        let (want_pk, want_sk) = internal::key_gen(ML_DSA_87, &[0x5a; 32]);
        assert_eq!(pk, want_pk);
        assert_eq!(*sk, *want_sk);
    }

    /// FIPS 204 Algorithm 3: a context over 255 bytes is an error, not a
    /// verdict; 255 bytes is allowed, and here merely fails to verify.
    #[test]
    fn a_context_over_255_bytes_is_an_error() {
        let p = ML_DSA_44;
        let pk = vec![0u8; p.public_key_len()];
        let sig = vec![0u8; p.signature_len()];
        assert_eq!(
            verify(p, &pk, b"m", &sig, &[0u8; 256]),
            Err(Error::ContextTooLong)
        );
        assert_eq!(verify(p, &pk, b"m", &sig, &[0u8; 255]), Ok(false));
    }

    /// FIPS 204 section 3.6.2: a public key or signature of any other
    /// length is answered with false, never decoded.
    #[test]
    fn a_key_or_signature_of_the_wrong_length_is_false() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            wrong_lengths_are_false(p);
        }
    }

    /// Every length one byte either side of the real one, for `pk` and for
    /// `sig`, at one parameter set.
    fn wrong_lengths_are_false(p: crate::ParameterSet) {
        let len = p.signature_len();
        let (pk, sig) = (vec![0u8; p.public_key_len()], vec![0u8; len]);
        for bad in [0, len - 1, len + 1] {
            assert_eq!(
                verify(p, &pk, b"m", &vec![0u8; bad], b""),
                Ok(false),
                "{}",
                p.name
            );
        }
        for bad in [0, pk.len() - 1, pk.len() + 1] {
            assert_eq!(
                verify(p, &vec![0u8; bad], b"m", &sig, b""),
                Ok(false),
                "{}",
                p.name
            );
        }
    }

    #[test]
    fn a_failing_source_is_an_error_not_a_seed() {
        let got = key_gen_seed_drawing_from(ML_DSA_87, |_| Err(Error::RandomnessUnavailable));
        assert_eq!(got.err(), Some(Error::RandomnessUnavailable));
    }

    /// Exactly one 32-byte seed is drawn; it is the seed returned, and the
    /// public key is the one key generation makes from it.
    #[test]
    fn the_seed_key_is_the_drawn_seed_and_its_public_key() {
        let mut drawn = Vec::new();
        let (pk, seed) = key_gen_seed_drawing_from(ML_DSA_87, |buf| {
            buf.fill(0x3c);
            drawn.push(buf.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(drawn, vec![32]);
        assert_eq!(*seed, [0x3c; 32]);
        assert_eq!(pk, internal::key_gen(ML_DSA_87, &[0x3c; 32]).0);
    }

    #[test]
    fn a_failing_source_is_an_error_not_a_signature() {
        let (_, sk) = internal::key_gen(ML_DSA_65, &[1; 32]);
        let got = sign_drawing_from(ML_DSA_65, PrivateKey::Expanded(&sk), b"m", b"", |_| {
            Err(Error::RandomnessUnavailable)
        });
        assert_eq!(got, Err(Error::RandomnessUnavailable));
    }

    /// Exactly one 32-byte `rnd` is drawn, and the signature is
    /// Algorithm 2's with that `rnd`: the hedge is the draw, and the public
    /// path adds nothing and drops nothing.
    #[test]
    fn the_signature_is_hedged_with_the_drawn_rnd() {
        let (_, sk) = internal::key_gen(ML_DSA_65, &[1; 32]);
        let key = PrivateKey::Expanded(&sk);
        let mut drawn = Vec::new();
        let sig = sign_drawing_from(ML_DSA_65, key, b"m", b"c", |buf| {
            buf.fill(0xa5);
            drawn.push(buf.len());
            Ok(())
        })
        .unwrap();
        assert_eq!(drawn, vec![32]);
        let want = internal::sign_message(ML_DSA_65, key, b"m", b"c", &[0xa5; 32]).unwrap();
        assert_eq!(sig, want);
        let deterministic = internal::sign_message(ML_DSA_65, key, b"m", b"c", &[0; 32]).unwrap();
        assert_ne!(sig, deterministic, "the drawn rnd was not used");
    }

    /// FIPS 204 Algorithm 2 checks the context before it draws anything.
    #[test]
    fn a_long_context_is_refused_before_anything_is_drawn() {
        let (_, sk) = internal::key_gen(ML_DSA_65, &[1; 32]);
        let got = sign_drawing_from(
            ML_DSA_65,
            PrivateKey::Expanded(&sk),
            b"m",
            &[0; 256],
            |_| panic!("randomness was drawn for a context that is refused"),
        );
        assert_eq!(got, Err(Error::ContextTooLong));
    }

    #[test]
    fn keys_from_the_os_have_the_standards_lengths_and_differ() {
        for p in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            let (pk1, sk1) = key_gen(p).unwrap();
            let (pk2, _) = key_gen(p).unwrap();
            assert_eq!(pk1.len(), p.public_key_len(), "{}", p.name);
            assert_eq!(sk1.len(), p.private_key_len(), "{}", p.name);
            assert_ne!(pk1, pk2, "{}: two draws gave one key", p.name);
        }
    }
}
