//! FIPS 204 section 7.1 and 7.2: packing polynomials and keys into bytes.
//!
//! Bits go out least significant first, FIPS 204 Algorithms 9 and 12
//! (`IntegerToBits`, `BitsToBytes`): value `i` occupies bits `i * bits`
//! to `i * bits + bits - 1` of the output, little-endian.

use crate::poly::{from_signed, sub, Poly, N};
use crate::sample::{K_MAX, L_MAX};
use crate::ParameterSet;

/// `bitlen(q - 1) - d`: the bits of each coefficient of `t1`.
pub const T1_BITS: usize = 10;

/// Packs 256 values of `bits` bits each into `out`, which is exactly
/// `32 * bits` bytes.
fn pack(value: impl Fn(usize) -> u32, bits: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * bits);
    let mut acc: u64 = 0;
    let mut held = 0;
    let mut o = 0;
    for i in 0..N {
        acc |= (value(i) as u64) << held;
        held += bits;
        while held >= 8 {
            out[o] = acc as u8;
            o += 1;
            acc >>= 8;
            held -= 8;
        }
    }
}

/// FIPS 204 Algorithm 16, `SimpleBitPack`, for coefficients in
/// `[0, 2^bits)`.
pub fn simple_bit_pack(w: &Poly, bits: usize, out: &mut [u8]) {
    pack(|i| w[i] as u32, bits, out);
}

/// FIPS 204 Algorithm 17, `BitPack`, for coefficients standing for values
/// in `[-a, b]`: each is packed as `b - w_i`, in `bitlen(a + b)` bits.
/// `w` holds the values mod q, and `b - w_i mod q` is exactly `b - v`
/// because it lands in `[0, a + b]`.
pub fn bit_pack(w: &Poly, b: i32, bits: usize, out: &mut [u8]) {
    pack(|i| sub(b, w[i]) as u32, bits, out);
}

/// FIPS 204 Algorithm 22, `pkEncode`, into `pk` of exactly
/// [`ParameterSet::public_key_len`] bytes.
pub fn pk_encode(pk: &mut [u8], rho: &[u8; 32], t1: &[Poly; K_MAX], p: ParameterSet) {
    pk[..32].copy_from_slice(rho);
    for (chunk, poly) in pk[32..]
        .as_chunks_mut::<{ 32 * T1_BITS }>()
        .0
        .iter_mut()
        .zip(t1)
        .take(p.k)
    {
        simple_bit_pack(poly, T1_BITS, chunk);
    }
}

/// FIPS 204 Algorithm 24, `skEncode`, into `sk` of exactly
/// [`ParameterSet::private_key_len`] bytes.
#[allow(clippy::too_many_arguments)]
pub fn sk_encode(
    sk: &mut [u8],
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8; 64],
    s1: &[Poly; L_MAX],
    s2: &[Poly; K_MAX],
    t0: &[Poly; K_MAX],
    p: ParameterSet,
) {
    sk[..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(key);
    sk[64..128].copy_from_slice(tr);
    let eb = p.eta_bits();
    let d = crate::D;
    let mut at = 128;
    for poly in s1.iter().take(p.l).chain(s2.iter().take(p.k)) {
        bit_pack(poly, p.eta, eb, &mut sk[at..at + 32 * eb]);
        at += 32 * eb;
    }
    for poly in t0.iter().take(p.k) {
        bit_pack(poly, 1 << (d - 1), d, &mut sk[at..at + 32 * d]);
        at += 32 * d;
    }
    debug_assert_eq!(at, sk.len());
}

/// Unpacks 256 values of `bits` bits each from `v`, exactly `32 * bits`
/// bytes, handing each to `put`.
fn unpack(v: &[u8], bits: usize, mut put: impl FnMut(usize, u32)) {
    debug_assert_eq!(v.len(), 32 * bits);
    let mask = (1u64 << bits) - 1;
    let mut acc: u64 = 0;
    let mut held = 0;
    let mut bytes = v.iter();
    for i in 0..N {
        while held < bits {
            acc |= (*bytes.next().expect("32 * bits bytes") as u64) << held;
            held += 8;
        }
        put(i, (acc & mask) as u32);
        acc >>= bits;
        held -= bits;
    }
}

/// FIPS 204 Algorithm 18, `SimpleBitUnpack`.
pub fn simple_bit_unpack(v: &[u8], bits: usize, w: &mut Poly) {
    unpack(v, bits, |i, x| w[i] = x as i32);
}

/// FIPS 204 Algorithm 19, `BitUnpack`: each value `x` becomes `b - x`, held
/// mod q.
pub fn bit_unpack(v: &[u8], b: i32, bits: usize, w: &mut Poly) {
    unpack(v, bits, |i, x| w[i] = from_signed(b - x as i32));
}

/// FIPS 204 Algorithm 23, `pkDecode`, of a public key of the right length.
pub fn pk_decode(pk: &[u8], p: ParameterSet) -> ([u8; 32], Box<[Poly; K_MAX]>) {
    let rho: [u8; 32] = pk[..32].try_into().expect("32 bytes");
    let mut t1 = Box::new([[0i32; N]; K_MAX]);
    for (chunk, poly) in pk[32..]
        .as_chunks::<{ 32 * T1_BITS }>()
        .0
        .iter()
        .zip(t1.iter_mut())
        .take(p.k)
    {
        simple_bit_unpack(chunk, T1_BITS, poly);
    }
    (rho, t1)
}

/// FIPS 204 Algorithm 21, `HintBitUnpack`: `None` for a malformed hint,
/// which is every check the standard lists: a count that runs backwards or
/// past omega, positions not strictly increasing within a polynomial, and
/// nonzero padding.
pub fn hint_bit_unpack(y: &[u8], p: ParameterSet) -> Option<Box<[Poly; K_MAX]>> {
    let omega = p.omega;
    let mut h = Box::new([[0i32; N]; K_MAX]);
    let mut index = 0;
    for (i, poly) in h.iter_mut().enumerate().take(p.k) {
        let end = y[omega + i] as usize;
        if end < index || end > omega {
            return None;
        }
        hint_positions(poly, y, index, end)?;
        index = end;
    }
    if y[index..omega].iter().any(|&b| b != 0) {
        return None;
    }
    Some(h)
}

/// The `first..end` run of one polynomial's positions in `y`: `None` when
/// they are not strictly increasing, or when `y[index - 1]` and `y[index]`
/// here are out of order.
fn hint_positions(poly: &mut Poly, y: &[u8], first: usize, end: usize) -> Option<()> {
    let mut index = first;
    while index < end {
        if index > first && y[index - 1] >= y[index] {
            return None;
        }
        poly[y[index] as usize] = 1;
        index += 1;
    }
    Some(())
}

/// A decoded signature: the commitment hash, the response `z` held mod q,
/// and the hint.
pub struct Signature<'a> {
    /// `c~`, lambda / 4 bytes.
    pub c_tilde: &'a [u8],
    /// `z`, `l` polynomials.
    pub z: Box<[Poly; L_MAX]>,
    /// `h`, `k` polynomials of 0 and 1.
    pub h: Box<[Poly; K_MAX]>,
}

/// FIPS 204 Algorithm 27, `sigDecode`, of a signature of the right length:
/// `None` when the hint is malformed.
pub fn sig_decode(sig: &[u8], p: ParameterSet) -> Option<Signature<'_>> {
    let c_len = p.lambda / 4;
    let zb = p.z_bits();
    let mut z = Box::new([[0i32; N]; L_MAX]);
    for (i, poly) in z.iter_mut().enumerate().take(p.l) {
        let at = c_len + i * 32 * zb;
        bit_unpack(&sig[at..at + 32 * zb], p.gamma1, zb, poly);
    }
    let h = hint_bit_unpack(&sig[c_len + p.l * 32 * zb..], p)?;
    Some(Signature {
        c_tilde: &sig[..c_len],
        z,
        h,
    })
}

/// FIPS 204 Algorithm 28, `w1Encode`, absorbed straight into `h` rather
/// than built as a byte string first.
pub fn w1_encode_into(h: &mut macula_keccak::Shake256, w1: &[Poly; K_MAX], p: ParameterSet) {
    let bits = p.w1_bits();
    let mut out = [0u8; 32 * 6];
    for poly in w1.iter().take(p.k) {
        simple_bit_pack(poly, bits, &mut out[..32 * bits]);
        h.update(&out[..32 * bits]);
    }
}

/// FIPS 204 Algorithm 25, `skDecode`, of a private key of the right
/// length: `s1`, `s2` and `t0` are written into the caller's wiped arrays,
/// and `(rho, K, tr)` returned, `K` wiped on drop.
///
/// The standard runs this on trusted input only, and so does this crate:
/// a malformed key yields signatures that do not verify, not a refusal.
pub fn sk_decode(
    sk: &[u8],
    p: ParameterSet,
    s1: &mut [Poly; L_MAX],
    s2: &mut [Poly; K_MAX],
    t0: &mut [Poly; K_MAX],
) -> ([u8; 32], zeroize::Zeroizing<[u8; 32]>, [u8; 64]) {
    let rho: [u8; 32] = sk[..32].try_into().expect("32 bytes");
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&sk[32..64]);
    let tr: [u8; 64] = sk[64..128].try_into().expect("64 bytes");
    let eb = p.eta_bits();
    let d = crate::D;
    let mut at = 128;
    for poly in s1.iter_mut().take(p.l).chain(s2.iter_mut().take(p.k)) {
        bit_unpack(&sk[at..at + 32 * eb], p.eta, eb, poly);
        at += 32 * eb;
    }
    for poly in t0.iter_mut().take(p.k) {
        bit_unpack(&sk[at..at + 32 * d], 1 << (d - 1), d, poly);
        at += 32 * d;
    }
    debug_assert_eq!(at, sk.len());
    (rho, key, tr)
}

/// FIPS 204 Algorithm 20, `HintBitPack`, into `y` of `omega + k` bytes, for
/// a hint of at most `omega` ones.
///
/// ⚠ NO BRANCH ON A HINT BIT. Every coefficient writes its position into
/// a scratch slot and the bit only decides whether the index advances; the
/// padding is masked arithmetically. The version that skipped the write
/// for each zero bit was the one timing difference the signing harness
/// found: the hint depends on the secret key, and at 40,000 measurements
/// fixed-versus-random secrets were flagged at |t| 9.73 and 15.15 (see
/// `examples/signing_timing.rs`). The hint is public, but a permitted difference
/// of that size would hide a real one.
pub fn hint_bit_pack(y: &mut [u8], h: &[Poly; K_MAX], p: ParameterSet) {
    let mut slots = [0u8; N + 1];
    let mut index = 0usize;
    for (i, poly) in h.iter().enumerate().take(p.k) {
        for (j, &bit) in poly.iter().enumerate() {
            slots[index] = j as u8;
            index += bit as usize;
        }
        y[p.omega + i] = index as u8;
    }
    for (s, out) in y[..p.omega].iter_mut().enumerate() {
        let keep = ((s as isize - index as isize) >> (isize::BITS - 1)) as u8;
        *out = slots[s] & keep;
    }
}

/// FIPS 204 Algorithm 26, `sigEncode`, for `z` held mod q with values in
/// `[-gamma1 + 1, gamma1]`.
pub fn sig_encode(
    c_tilde: &[u8],
    z: &[Poly; L_MAX],
    h: &[Poly; K_MAX],
    p: ParameterSet,
) -> Vec<u8> {
    let mut sig = vec![0u8; p.signature_len()];
    let c_len = p.lambda / 4;
    sig[..c_len].copy_from_slice(c_tilde);
    let zb = p.z_bits();
    for (i, poly) in z.iter().enumerate().take(p.l) {
        let at = c_len + i * 32 * zb;
        bit_pack(poly, p.gamma1, zb, &mut sig[at..at + 32 * zb]);
    }
    hint_bit_pack(&mut sig[c_len + p.l * 32 * zb..], h, p);
    sig
}
