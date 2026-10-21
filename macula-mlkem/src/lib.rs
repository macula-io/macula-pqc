//! ML-KEM (FIPS 203), implemented here rather than depended on.
//!
//! **Built on `macula-keccak`, deliberately.** FIPS 203 is built on
//! SHA3-256, SHA3-512, SHAKE128 and SHAKE256, so implementing ML-KEM while
//! taking Keccak from a third party would relocate the dependency rather
//! than remove it.
//!
//! # API
//!
//! - [`key_gen`] and [`encaps`]: FIPS 203 Algorithms 19 and 20. Their
//!   seeds are drawn from the OS, and if it cannot supply them the result
//!   is [`Error::RandomnessUnavailable`], as those algorithms require.
//! - [`decaps`]: Algorithm 18, with implicit rejection. A ciphertext that
//!   does not re-encrypt yields a pseudorandom secret, not an error.
//! - [`encaps_key_valid`] and [`decaps_key_valid`]: the section 7.2 and
//!   7.3 input checks.
//!
//! # Randomness comes from the OS, and nothing else
//!
//! Not `aws-lc-rs`, and not ours: a hand-written CSPRNG is the one piece of
//! this workspace where rolling your own would be unambiguously wrong,
//! because randomness has no test vectors. You cannot test that output is
//! unpredictable, so it is the one place a bug would be invisible to the
//! method everything else here relies on.
//!
//! # Wiping secrets
//!
//! Every secret is wiped when it is dropped, using the `zeroize` crate:
//! seeds, the secret key, noise polynomials, the message, shared secrets,
//! and the values decryption derives from them. What a caller receives
//! that is secret comes as [`Zeroizing`], which wipes itself too: the
//! decapsulation key and the shared secret. Every buffer holding a secret
//! is allocated at its final size, because a buffer that grows leaves a
//! copy of its old contents behind.
//!
//! **The heap is measured**: `tests/heap_residue.rs` scans every block
//! freed during key generation, encapsulation and both kinds of
//! decapsulation for that run's secrets, and finds none. **The stack is
//! wiped by construction**, which safe code cannot observe, and copies the
//! compiler makes when it moves or spills a value are beyond any of it, as
//! `zeroize` itself states.
//!
//! # The `internal` feature
//!
//! Key generation and encapsulation with caller-supplied seeds (FIPS 203
//! Algorithms 16 and 17), and the arithmetic, are public only with the
//! `internal` feature, and it is for testing. FIPS 203 sections 3.3 and 6
//! say those interfaces "should not be made available to applications
//! other than for testing purposes": whoever chooses `m` knows the shared
//! secret. They exist because NIST's vectors supply `d`, `z` and `m`
//! directly, which is what makes byte-exact verification possible at all.
//!
//! # Verification
//!
//! Byte-exact against NIST's ACVP vectors, at ML-KEM-512, -768 and -1024:
//! key generation, encapsulation, decapsulation and both key checks, 240
//! cases, with the fifteen implicit-rejection cases each identified by
//! NIST's own label (`tests/acvp.rs`; provenance in `vectors/README.md`).
//!
//! # Timing: measured, and what that means
//!
//! `scripts/timing.sh` times decapsulation and encapsulation in a release
//! build. Its verdict is only worth something because it is calibrated:
//! its positive control is a leak of the size the constant-time compare
//! exists to prevent, planted after a real decapsulation. A copy of
//! [`decaps`] with that compare replaced by `==` and a branch is flagged by
//! the valid-against-invalid test. A dudect-style harness testing the two
//! classes as independent samples did not flag that copy at 100,000
//! measurements; see `examples/timing.rs` for the method and the confounds
//! its negative control exposed. The latest result is in the workspace
//! README.
//!
//! **"No division on secret data" is asserted by construction, not
//! established by that harness**, which has never been calibrated against
//! a planted division. Compression multiplies and shifts, ByteDecode at
//! 12 bits subtracts under a mask, and compression is tested equal to the
//! division formula for every input. The only `/` and `%` left are
//! evaluated at compile time, or divide loop counters, bit indices and
//! public bytes by powers of two.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// The seeded algorithms and the arithmetic are public only with the
// `internal` feature, which is for testing: see `internal`'s docs.
#[cfg(feature = "internal")]
pub mod encode;
#[cfg(not(feature = "internal"))]
mod encode;
mod hash;
#[cfg(feature = "internal")]
pub mod internal;
#[cfg(not(feature = "internal"))]
mod internal;
mod kpke;
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

/// A FIPS 203 parameter set.
///
/// The fields are the specification's own names, so a reader can check
/// them against Table 2 rather than against this comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterSet {
    /// The name the ACVP vectors use, e.g. `"ML-KEM-1024"`.
    pub name: &'static str,
    /// `k`: the dimension of the module, the number of polynomials in a
    /// vector and the rows and columns of the matrix `A`.
    pub k: usize,
    /// `eta_1`: the centred binomial width for the secret `s`, the error
    /// `e`, and encryption's `y`.
    pub eta1: usize,
    /// `eta_2`: the centred binomial width for encryption's `e_1` and `e_2`.
    pub eta2: usize,
    /// `d_u`: the bits kept per coefficient of `u` in the ciphertext.
    pub du: usize,
    /// `d_v`: the bits kept per coefficient of `v` in the ciphertext.
    pub dv: usize,
}

/// ML-KEM-512, security category 1.
pub const ML_KEM_512: ParameterSet = ParameterSet {
    name: "ML-KEM-512",
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};
/// ML-KEM-768, security category 3.
pub const ML_KEM_768: ParameterSet = ParameterSet {
    name: "ML-KEM-768",
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};
/// ML-KEM-1024, security category 5.
pub const ML_KEM_1024: ParameterSet = ParameterSet {
    name: "ML-KEM-1024",
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

/// Why an operation refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An encapsulation key failed the FIPS 203 section 7.2 check.
    EncapsKeyInvalid,
    /// A decapsulation key failed the FIPS 203 section 7.3 check.
    DecapsKeyInvalid,
    /// A byte string was not the length its parameter set requires.
    WrongLength,
    /// The OS could not supply randomness. FIPS 203 Algorithms 19 and 20
    /// return an error here rather than build anything from a seed that
    /// was not drawn.
    RandomnessUnavailable,
}

/// FIPS 203 Algorithm 19, `ML-KEM.KeyGen`: `d` and `z` are drawn from the
/// OS.
///
/// Returns `(ek, dk)`. `dk` wipes itself when dropped.
pub fn key_gen(p: ParameterSet) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    key_gen_drawing_from(p, os_random)
}

/// FIPS 203 Algorithm 20, `ML-KEM.Encaps`, preceded by the section 7.2
/// input check: `m` is drawn from the OS.
///
/// Returns `(c, k)`: the ciphertext to send, and the shared secret, which
/// wipes itself when dropped.
pub fn encaps(p: ParameterSet, ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    encaps_drawing_from(p, ek, os_random)
}

/// [`key_gen`] with its randomness source as a parameter, so the tests
/// can see what is drawn and make the source fail.
fn key_gen_drawing_from(
    p: ParameterSet,
    mut random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let mut d = Zeroizing::new([0u8; 32]);
    let mut z = Zeroizing::new([0u8; 32]);
    random(&mut *d)?;
    random(&mut *z)?;
    Ok(internal::key_gen(p, &d, &z))
}

/// [`encaps`] with its randomness source as a parameter.
fn encaps_drawing_from(
    p: ParameterSet,
    ek: &[u8],
    mut random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
    let mut m = Zeroizing::new([0u8; 32]);
    random(&mut *m)?;
    internal::encaps(p, ek, &m)
}

/// The OS CSPRNG, and nothing else: see the crate docs.
fn os_random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::RandomnessUnavailable)
}

/// `384k + 32` bytes: `k` polynomials at 12 bits, then `rho`.
fn encaps_key_len(p: ParameterSet) -> usize {
    384 * p.k + 32
}

/// FIPS 203 Algorithm 18.
///
/// ⛔ Returns a DETERMINISTIC PSEUDORANDOM SECRET for a ciphertext that
/// does not re-encrypt, NOT an error. That is the implicit rejection path,
/// and an implementation that returns an error instead passes every
/// happy-path vector while failing half the decapsulation ones.
///
/// The shared secret wipes itself when dropped.
pub fn decaps(p: ParameterSet, dk: &[u8], c: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    // FIPS 203 section 7.3 input checks. These inspect lengths and the
    // public half of dk, so early exits here leak nothing secret.
    if c.len() != ciphertext_len(p) || dk.len() != decaps_key_len(p) {
        return Err(Error::WrongLength);
    }
    if !decaps_key_valid(p, dk) {
        return Err(Error::DecapsKeyInvalid);
    }

    let k = p.k;
    let dk_pke = &dk[..384 * k];
    let ek_pke = &dk[384 * k..768 * k + 32];
    let h = &dk[768 * k + 32..768 * k + 64];
    let z = &dk[768 * k + 64..768 * k + 96];

    let m_prime = kpke::decrypt(p, dk_pke, c);
    let mut seed = Zeroizing::new([0u8; 64]);
    seed[..32].copy_from_slice(&*m_prime);
    seed[32..].copy_from_slice(h);
    let (k_prime, r_prime) = hash::g(&*seed);

    // z || c, allocated at its final size so it never moves: z is secret.
    let mut rejection_input = Zeroizing::new(Vec::with_capacity(32 + c.len()));
    rejection_input.extend_from_slice(z);
    rejection_input.extend_from_slice(c);
    let k_bar = hash::j(&rejection_input);

    // ⛔ Re-encrypt and compare IN CONSTANT TIME. A `==` on these slices
    // exits at the first differing byte, and how far it got tells an
    // attacker how much of a forged ciphertext decrypted consistently.
    // Then select, also without a branch: implicit rejection returns the
    // pseudorandom k_bar for a bad ciphertext, never an error.
    let c_prime = kpke::encrypt(p, ek_pke, &m_prime, &r_prime);
    Ok(Zeroizing::new(ct_select(
        ct_eq(c, &c_prime),
        &k_prime,
        &k_bar,
    )))
}

/// `32 * (du * k + dv)` bytes.
fn ciphertext_len(p: ParameterSet) -> usize {
    32 * (p.du * p.k + p.dv)
}

/// `768k + 96` bytes: dk_pke, ek, H(ek), z.
fn decaps_key_len(p: ParameterSet) -> usize {
    768 * p.k + 96
}

/// `0xFF` if `a == b`, `0x00` otherwise, examining every byte.
///
/// The fold never exits early and the final mapping is arithmetic.
/// `black_box` asks the optimiser not to turn either back into a branch;
/// it is a best effort, not a guarantee, and whether it holds is what the
/// timing harness exists to measure.
fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    let diff = core::hint::black_box(diff) as u16;
    // diff == 0 -> 0xFFFF >> 8 = 0xFF; diff in 1..=255 -> 0.
    (diff.wrapping_sub(1) >> 8) as u8
}

/// `a` where `mask` is `0xFF`, `b` where it is `0x00`, bytewise, with no
/// branch on the mask.
fn ct_select(mask: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mask = core::hint::black_box(mask);
    let mut out = [0u8; 32];
    for ((o, x), y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *o = (x & mask) | (y & !mask);
    }
    out
}

/// FIPS 203 section 7.2: the encapsulation key check.
///
/// The length is right, and every 12-bit coefficient is already reduced:
/// decoding then re-encoding must give back the same bytes. A value in
/// `[q, 4096)` would be silently reduced by decoding, so it shows up as a
/// difference here. `ek` is public, so an early exit is fine.
pub fn encaps_key_valid(p: ParameterSet, ek: &[u8]) -> bool {
    ek.len() == encaps_key_len(p)
        && ek[..384 * p.k].as_chunks::<384>().0.iter().all(|chunk| {
            let mut again = [0u8; 384];
            encode::byte_encode(12, &encode::byte_decode(12, chunk), &mut again);
            again == *chunk
        })
}

/// FIPS 203 section 7.3: the decapsulation key check.
///
/// The length is right, and the stored `H(ek)` matches the `ek` stored
/// beside it. Both are public, so an early exit is fine.
pub fn decaps_key_valid(p: ParameterSet, dk: &[u8]) -> bool {
    let k = p.k;
    dk.len() == decaps_key_len(p)
        && hash::h(&dk[384 * k..768 * k + 32]) == dk[768 * k + 32..768 * k + 64]
}

#[cfg(test)]
mod tests {
    use super::{
        ct_eq, ct_select, encaps_drawing_from, internal, key_gen_drawing_from, Error, ParameterSet,
        ML_KEM_1024, ML_KEM_512, ML_KEM_768,
    };

    const SETS: [ParameterSet; 3] = [ML_KEM_512, ML_KEM_768, ML_KEM_1024];

    /// A source that hands out 0, 1, 2, ... in order, so a test can tell
    /// which drawn bytes went where.
    fn counting() -> impl FnMut(&mut [u8]) -> Result<(), Error> {
        let mut next = 0u8;
        move |buf| {
            fill_counting(buf, &mut next);
            Ok(())
        }
    }

    /// The bytes `counting` hands out, in order across calls.
    fn fill_counting(buf: &mut [u8], next: &mut u8) {
        for b in buf.iter_mut() {
            *b = *next;
            *next = next.wrapping_add(1);
        }
    }

    /// A source that works `ok` times and then fails.
    fn failing_after(ok: usize) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
        let mut calls = 0;
        move |buf| draw_until_failure(ok, &mut calls, buf)
    }

    /// One draw from `failing_after`: count it, and fail once `ok` draws
    /// have already succeeded.
    fn draw_until_failure(ok: usize, calls: &mut usize, buf: &mut [u8]) -> Result<(), Error> {
        *calls += 1;
        if *calls > ok {
            return Err(Error::RandomnessUnavailable);
        }
        buf.fill(0x42);
        Ok(())
    }

    /// The drawn bytes ARE the seeds: `d` first, then `z`, as FIPS 203
    /// Algorithm 19 draws them.
    #[test]
    fn key_gen_uses_the_drawn_bytes_as_d_then_z() {
        let d: [u8; 32] = core::array::from_fn(|i| i as u8);
        let z: [u8; 32] = core::array::from_fn(|i| 32 + i as u8);
        for p in SETS {
            assert_eq!(
                key_gen_drawing_from(p, counting()).unwrap(),
                internal::key_gen(p, &d, &z),
                "{}",
                p.name
            );
        }
    }

    #[test]
    fn encaps_uses_the_drawn_bytes_as_m() {
        let m: [u8; 32] = core::array::from_fn(|i| i as u8);
        for p in SETS {
            let (ek, _) = internal::key_gen(p, &[1; 32], &[2; 32]);
            assert_eq!(
                encaps_drawing_from(p, &ek, counting()),
                internal::encaps(p, &ek, &m),
                "{}",
                p.name
            );
        }
    }

    /// FIPS 203 Algorithms 19 and 20: if random generation fails, return
    /// an error. Not a key built from whatever the buffer held, and not a
    /// panic. Failing on the SECOND draw is the case a `?` on only the
    /// first one would miss.
    #[test]
    fn a_failing_source_is_an_error_not_a_key() {
        for p in SETS {
            key_gen_from_a_failing_source_is_an_error(p);
            let (ek, _) = internal::key_gen(p, &[1; 32], &[2; 32]);
            assert_eq!(
                encaps_drawing_from(p, &ek, failing_after(0)),
                Err(Error::RandomnessUnavailable),
                "{}: encaps",
                p.name
            );
        }
    }

    /// A source failing after each of the two key-gen draws in turn.
    fn key_gen_from_a_failing_source_is_an_error(p: ParameterSet) {
        for ok in [0, 1] {
            assert_eq!(
                key_gen_drawing_from(p, failing_after(ok)),
                Err(Error::RandomnessUnavailable),
                "{}: key_gen, source fails after {ok} draws",
                p.name
            );
        }
    }

    /// A difference anywhere must be seen, including in the LAST byte. The
    /// ACVP rejection cases do not say where their ciphertexts were
    /// modified, so a comparison that stopped partway could pass them all.
    #[test]
    fn ct_eq_sees_a_difference_in_any_position() {
        let a = [7u8; 1568];
        assert_eq!(ct_eq(&a, &a), 0xff);
        for pos in [0usize, 1, 783, 1566, 1567] {
            let mut b = a;
            b[pos] ^= 0x01;
            assert_eq!(ct_eq(&a, &b), 0x00, "difference at byte {pos} not seen");
        }
    }

    /// Every one of the 255 non-zero single-byte differences maps to 0x00.
    /// `(diff - 1) >> 8` is the part that could be off by one.
    #[test]
    fn ct_eq_maps_every_nonzero_difference_to_false() {
        for bit in 1u8..=255 {
            assert_eq!(ct_eq(&[0u8], &[bit]), 0x00, "difference {bit:#04x}");
        }
    }

    #[test]
    fn ct_select_takes_a_on_ff_and_b_on_00() {
        let a = [0xaau8; 32];
        let b = [0x55u8; 32];
        assert_eq!(ct_select(0xff, &a, &b), a);
        assert_eq!(ct_select(0x00, &a, &b), b);
    }
}
