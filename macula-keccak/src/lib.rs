//! Keccak-f\[1600\], SHA3-256/512 and SHAKE128/256.
//!
//! # Why this is built here
//!
//! FIPS 203 (ML-KEM) is built on SHA3-256, SHA3-512, SHAKE128 and
//! SHAKE256, and FIPS 204 (ML-DSA) on SHAKE128 and SHAKE256. Implementing
//! either while taking Keccak from a third party would relocate the
//! dependency rather than remove it.
//!
//! # Timing: an argument from the algorithm's shape
//!
//! Keccak-f\[1600\] is a fixed permutation of bitwise operations over a
//! fixed-size state. **There is no secret-dependent branch or table index
//! to write**, because nothing in the permutation is data-dependent: the
//! round count is fixed, the rotation offsets are compile-time constants,
//! and the round constants are indexed by the round number rather than by
//! any input. Absorption and squeezing are driven by message and output
//! LENGTHS, which are public.
//!
//! ⚠ THAT IS AN ARGUMENT FROM THE ALGORITHM'S SHAPE, NOT A MEASUREMENT,
//! and the distinction is the point rather than a caveat.
//!
//! "Written without secret-dependent branches" is a claim about the
//! author's intentions. A timing measurement is evidence. This crate is
//! measured only inside `macula-mlkem`, whose timing harness hashes
//! secret data through it; on its own it claims only what it avoids by
//! construction.
//!
//! # Wiping
//!
//! The sponge state after absorbing a short message can be run backwards
//! to it, so when the message is secret, so is the state. The one-shot
//! functions wipe their state, and the padded final block, before
//! returning. [`Shake128Reader`], [`Shake256`] and [`Shake256Reader`] wipe
//! their state and any buffered block when dropped. Outputs are the
//! caller's to wipe.
//!
//! # Verification
//!
//! Byte-exact against NIST's own ACVP vectors, vendored under `vectors/`
//! with their provenance and checksums. See that directory's README for
//! why both the `-1.0` and `-FIPS202` vector sets are used: the one named
//! after the standard never exercises a multi-block squeeze.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Rate in bytes for each function, from FIPS 202: rate = 200 - 2 * (security strength / 8).
const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

/// Domain separation suffixes, FIPS 202 section 6.1 and 6.2.
const SHA3_PAD: u8 = 0x06;
const SHAKE_PAD: u8 = 0x1f;

/// SHA3-256.
pub fn sha3_256(msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sponge::<SHA3_256_RATE>(msg, SHA3_PAD, &mut out);
    out
}

/// SHA3-512.
pub fn sha3_512(msg: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    sponge::<SHA3_512_RATE>(msg, SHA3_PAD, &mut out);
    out
}

/// SHAKE128 as a one-shot XOF of the caller's chosen length.
pub fn shake128(msg: &[u8], out: &mut [u8]) {
    sponge::<SHAKE128_RATE>(msg, SHAKE_PAD, out);
}

/// SHAKE256 as a one-shot XOF of the caller's chosen length.
pub fn shake256(msg: &[u8], out: &mut [u8]) {
    sponge::<SHAKE256_RATE>(msg, SHAKE_PAD, out);
}

/// An incremental SHAKE128 reader.
///
/// ML-KEM squeezes SHAKE128 repeatedly to expand its matrix and does not
/// know in advance how many bytes it will need, because it rejects
/// out-of-range samples. So the sponge state has to be carried across
/// calls, which is the part of an XOF that goes wrong and the part the
/// `-FIPS202` vectors never reach.
pub struct Shake128Reader(Squeeze<SHAKE128_RATE>);

impl ZeroizeOnDrop for Shake128Reader {}

impl Shake128Reader {
    /// Absorb `msg` and prepare to squeeze.
    pub fn new(msg: &[u8]) -> Self {
        let mut a = Absorb::<SHAKE128_RATE>::new();
        a.update(msg);
        Self(Squeeze::from_absorbed(a.finish(SHAKE_PAD)))
    }

    /// Squeeze the next `out.len()` bytes, continuing where the last call
    /// stopped.
    pub fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// SHAKE256, absorbing its input in pieces.
///
/// ML-DSA hashes several inputs as one message: a secret key with its
/// signing randomness, or a public-key hash with a message of any length.
/// Absorbing them piece by piece means neither a secret nor a long message
/// is copied into a concatenation buffer, which for a secret would be one
/// more thing to wipe. Pieces of any size, empty ones included, give the
/// same output as the one-shot [`shake256`] over their concatenation.
pub struct Shake256(Absorb<SHAKE256_RATE>);

impl ZeroizeOnDrop for Shake256 {}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    /// An empty SHAKE256, ready to absorb.
    pub fn new() -> Self {
        Self(Absorb::new())
    }

    /// Absorb the next piece of the input.
    pub fn update(&mut self, piece: &[u8]) {
        self.0.update(piece);
    }

    /// Finish absorbing and start squeezing.
    pub fn finalize_xof(self) -> Shake256Reader {
        Shake256Reader(Squeeze::from_absorbed(self.0.finish(SHAKE_PAD)))
    }
}

/// An incremental SHAKE256 reader, from [`Shake256::finalize_xof`].
///
/// ML-DSA squeezes SHAKE256 as far as its rejection sampling asks, when it
/// samples its secret vectors and its challenge.
pub struct Shake256Reader(Squeeze<SHAKE256_RATE>);

impl ZeroizeOnDrop for Shake256Reader {}

impl Shake256Reader {
    /// Squeeze the next `out.len()` bytes, continuing where the last call
    /// stopped.
    pub fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

// ---------------------------------------------------------------------
// The sponge
// ---------------------------------------------------------------------
//
// ONE absorbing half and ONE squeezing half, generic over the rate, serve
// every function above: the one-shot hashes, both readers and the
// incremental SHAKE256. A second absorb for the incremental case would be
// a second copy of the padding rule, and the two could disagree on
// exactly the inputs that end on a block boundary.

fn sponge<const RATE: usize>(msg: &[u8], pad: u8, out: &mut [u8]) {
    let mut a = Absorb::<RATE>::new();
    a.update(msg);
    let mut s = Squeeze::<RATE>::from_absorbed(a.finish(pad));
    s.read(out);
}

/// The absorbing half: whole blocks are XORed in and permuted as they
/// fill; a partial block waits in `block` for the next piece or the
/// padding.
struct Absorb<const RATE: usize> {
    state: [u64; 25],
    block: [u8; RATE],
    /// Bytes of `block` filled, always below `RATE` between calls: a full
    /// block is absorbed at once.
    filled: usize,
}

impl<const RATE: usize> Drop for Absorb<RATE> {
    fn drop(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
    }
}

impl<const RATE: usize> Absorb<RATE> {
    fn new() -> Self {
        Self {
            state: [0u64; 25],
            block: [0u8; RATE],
            filled: 0,
        }
    }

    fn update(&mut self, mut piece: &[u8]) {
        while !piece.is_empty() {
            let take = core::cmp::min(RATE - self.filled, piece.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&piece[..take]);
            self.filled += take;
            piece = &piece[take..];
            self.absorb_if_full();
        }
    }

    /// Absorb the block and permute it, once a whole block is filled.
    fn absorb_if_full(&mut self) {
        if self.filled != RATE {
            return;
        }
        xor_block(&mut self.state, &self.block);
        keccak_f1600(&mut self.state);
        self.filled = 0;
    }

    /// Apply the pad10*1 rule with the domain separation suffix, FIPS 202
    /// section 5.1, and absorb the final block. The returned state is the
    /// caller's to wipe; this one wipes itself as it drops.
    fn finish(mut self, pad: u8) -> [u64; 25] {
        let filled = self.filled;
        self.block[filled..].fill(0);
        self.block[filled] ^= pad;
        self.block[RATE - 1] ^= 0x80;
        let mut state = self.state;
        xor_block(&mut state, &self.block);
        keccak_f1600(&mut state);
        state
    }
}

/// The squeezing half.
struct Squeeze<const RATE: usize> {
    state: [u64; 25],
    buf: [u8; RATE],
    /// Bytes of `buf` already handed out. `RATE` means "empty".
    used: usize,
}

impl<const RATE: usize> Drop for Squeeze<RATE> {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

impl<const RATE: usize> Squeeze<RATE> {
    /// ⚠ `Absorb::finish` ENDS with a permutation, so the first output
    /// block comes from the state as it stands. Permuting again here would
    /// make every first block the SECOND block, which is wrong for every
    /// input and was this crate's first bug.
    fn from_absorbed(mut state: [u64; 25]) -> Self {
        let mut buf = [0u8; RATE];
        squeeze_block(&state, &mut buf);
        let s = Self {
            state,
            buf,
            used: 0,
        };
        state.zeroize();
        buf.zeroize();
        s
    }

    fn read(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            self.refill_if_spent();
            let take = core::cmp::min(RATE - self.used, out.len() - done);
            out[done..done + take].copy_from_slice(&self.buf[self.used..self.used + take]);
            self.used += take;
            done += take;
        }
    }

    /// Permute and squeeze a fresh output block once the buffer is spent.
    fn refill_if_spent(&mut self) {
        if self.used != RATE {
            return;
        }
        keccak_f1600(&mut self.state);
        squeeze_block(&self.state, &mut self.buf);
        self.used = 0;
    }
}

fn xor_block(state: &mut [u64; 25], block: &[u8]) {
    for (i, word) in block.as_chunks::<8>().0.iter().enumerate() {
        state[i] ^= u64::from_le_bytes(*word);
    }
    // A rate is always a multiple of 8 for every function here, so there
    // is no partial trailing word to handle.
}

fn squeeze_block(state: &[u64; 25], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let bytes = state[i].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

// ---------------------------------------------------------------------
// Keccak-f[1600]
// ---------------------------------------------------------------------

/// Round constants, FIPS 202 section 3.2.5. Indexed by ROUND NUMBER,
/// never by data.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for rho, FIPS 202 section 3.2.2. Compile-time
/// constants, not data-dependent.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation for pi, FIPS 202 section 3.2.3.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// One round of keccak-f[1600], FIPS 202 section 3.2: theta, rho and pi,
/// chi, iota.
#[inline]
fn round(a: &mut [u64; 25], rc: u64) {
    // theta
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            a[x + 5 * y] ^= d;
        }
    }
    // rho and pi
    let mut last = a[1];
    for i in 0..24 {
        let j = PI[i];
        let tmp = a[j];
        a[j] = last.rotate_left(RHO[i]);
        last = tmp;
    }
    chi(a);
    // iota
    a[0] ^= rc;
}

/// chi, FIPS 202 section 3.2.4: the only non-linear step.
#[inline]
fn chi(a: &mut [u64; 25]) {
    for y in 0..5 {
        let row = [
            a[5 * y],
            a[5 * y + 1],
            a[5 * y + 2],
            a[5 * y + 3],
            a[5 * y + 4],
        ];
        for x in 0..5 {
            a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
        }
    }
}

fn keccak_f1600(a: &mut [u64; 25]) {
    for rc in RC {
        round(a, rc);
    }
}
