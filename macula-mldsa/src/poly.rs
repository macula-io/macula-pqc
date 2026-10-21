//! Arithmetic in `Z_q[X]/(X^256 + 1)` for `q = 8380417`, per FIPS 204.
//!
//! ⚠ No secret-dependent branch or index is written here by construction:
//! reduction is Barrett, comparisons are arithmetic, and every loop bound
//! is a compile-time constant. That is a statement about the code's shape
//! and **not a measurement**.

use crate::Q;

/// The degree of the ring.
pub const N: usize = 256;

/// A polynomial, coefficients in `[0, q)`. A coefficient that stands for
/// a small signed value `v` holds `v mod q`.
pub type Poly = [i32; N];

/// `a mod q`, for `a` in `[0, 2^48)`: every product of two coefficients
/// and every sum of a few. No branch on the value.
///
/// Barrett with `V = floor(2^70 / q)`: `a * V / 2^70` undershoots `a / q`
/// by less than `a / 2^70 < 2^-22`, so the quotient estimate is the true
/// one or one below, the remainder is in `[0, 2q)`, and one masked
/// subtraction finishes it. The product needs 95 bits, hence u128.
#[inline(always)]
pub fn reduce(a: u64) -> i32 {
    const V: u128 = (1u128 << 70) / Q as u128;
    let t = ((a as u128 * V) >> 70) as u64;
    let r = (a - t * Q as u64) as i64 - Q as i64;
    (r + ((r >> 63) & Q as i64)) as i32
}

/// `a * b mod q`, for `a` and `b` in `[0, q)`.
#[inline(always)]
pub fn mul(a: i32, b: i32) -> i32 {
    reduce(a as u64 * b as u64)
}

/// `a + b mod q`, for `a` and `b` in `[0, q)`, subtracting `q` under a
/// mask rather than a branch.
#[inline(always)]
pub fn add(a: i32, b: i32) -> i32 {
    let s = a + b - Q;
    s + ((s >> 31) & Q)
}

/// `a - b mod q`, for `a` and `b` in `[0, q)`, adding `q` under a mask
/// rather than a branch.
#[inline(always)]
pub fn sub(a: i32, b: i32) -> i32 {
    let d = a - b;
    d + ((d >> 31) & Q)
}

/// A small signed value `v`, `|v| < q`, as a coefficient: `v mod q`.
#[inline(always)]
pub fn from_signed(v: i32) -> i32 {
    v + ((v >> 31) & Q)
}

/// `zetas[k] = zeta^BitRev8(k) mod q` for `zeta = 1753`, FIPS 204 section
/// 7.5, built at COMPILE TIME rather than transcribed. `zetas[0]` is
/// unused and 0, as in Appendix B.
///
/// ⚠ A hand-copied table would be a second place for the contract to live,
/// and a single mistyped digit produces a coherent-looking implementation
/// that fails every vector with no hint where. The unit tests hold
/// Appendix B's table, extracted from the standard, to check this one.
pub const ZETAS: [i32; N] = build_zetas();

const fn build_zetas() -> [i32; N] {
    let mut out = [0i32; N];
    let mut k = 1;
    while k < N {
        out[k] = pow1753(bit_rev8(k));
        k += 1;
    }
    out
}

/// The eight-bit reversal of `k`, FIPS 204's `BitRev8`.
const fn bit_rev8(k: usize) -> usize {
    let mut r = 0usize;
    let mut b = 0;
    while b < 8 {
        r |= ((k >> b) & 1) << (7 - b);
        b += 1;
    }
    r
}

/// `1753^r mod q` by square and multiply.
const fn pow1753(r: usize) -> i32 {
    let mut acc: u64 = 1;
    let mut base: u64 = 1753;
    let mut e = r;
    while e > 0 {
        if e & 1 == 1 {
            acc = acc * base % Q as u64;
        }
        base = base * base % Q as u64;
        e >>= 1;
    }
    acc as i32
}

/// FIPS 204 Algorithm 41, `NTT`, in place.
pub fn ntt(w: &mut Poly) {
    let mut m = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            let z = ZETAS[m];
            butterfly(w, start, len, z);
            start += 2 * len;
        }
        len /= 2;
    }
}

/// One row of the forward butterfly: the `j`/`j + len` pair in a block.
#[inline(always)]
fn butterfly(w: &mut Poly, start: usize, len: usize, z: i32) {
    for j in start..start + len {
        let t = mul(z, w[j + len]);
        w[j + len] = sub(w[j], t);
        w[j] = add(w[j], t);
    }
}

/// FIPS 204 Algorithm 42, `NTT^-1`, in place.
pub fn ntt_inverse(w: &mut Poly) {
    let mut m = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            inverse_butterfly(w, start, len, Q - ZETAS[m]);
            start += 2 * len;
        }
        len *= 2;
    }
    // f = 256^-1 mod q.
    const F: i32 = 8347681;
    for c in w.iter_mut() {
        *c = mul(F, *c);
    }
}

/// One row of the inverse butterfly: the `j`/`j + len` pair in a block.
#[inline(always)]
fn inverse_butterfly(w: &mut Poly, start: usize, len: usize, z: i32) {
    for j in start..start + len {
        let t = w[j];
        w[j] = add(t, w[j + len]);
        w[j + len] = mul(z, sub(t, w[j + len]));
    }
}

/// The coefficient-wise product of two NTT-domain polynomials, FIPS 204
/// Algorithm 45, added into `acc`: the inner step of a matrix-vector
/// product (Algorithm 48).
pub fn multiply_add_ntt(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] = add(acc[i], mul(a[i], b[i]));
    }
}

/// FIPS 204 Algorithm 35, `Power2Round`, for `r` in `[0, q)`: returns
/// `(r1, r0)` with `r = r1 * 2^d + r0` and `r0` in `[-2^(d-1) + 1,
/// 2^(d-1)]`, `r0` as a signed integer.
pub fn power2round(r: i32) -> (i32, i32) {
    const D: i32 = crate::D as i32;
    let low = r & ((1 << D) - 1);
    // mod+-: fold the upper half of [0, 2^d) down by 2^d, under a mask.
    let r0 = low - ((((1 << (D - 1)) - low) >> 31) & (1 << D));
    ((r - r0) >> D, r0)
}

/// `x / alpha`, floored, for `x < 2^24` and `alpha > 2^17`, by a multiply
/// and a shift rather than a divide instruction: a hardware divide can
/// take a time that depends on its operands, and signing decomposes
/// values derived from its secret mask.
///
/// `m = ceil(2^48 / alpha)` overshoots `2^48 / alpha` by less than 1, so
/// `x * m / 2^48` overshoots `x / alpha` by less than `2^24 / 2^48`, below
/// the `1 / alpha` it would take to cross an integer. `m` itself is
/// computed from the public `alpha`.
#[inline(always)]
fn div_floor(x: i32, alpha: i32) -> i32 {
    let m = (1u64 << 48).div_ceil(alpha as u64);
    ((x as u64 * m) >> 48) as i32
}

/// FIPS 204 Algorithm 36, `Decompose`, for `r` in `[0, q)`: `(r1, r0)` with
/// `r = r1 * 2 gamma2 + r0` and `r0` in `(-gamma2, gamma2]`, except that
/// when `r - r0 = q - 1` it returns `(0, r0 - 1)`. No branch on `r`.
#[inline(always)]
pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;
    // r0 in (-gamma2, gamma2] makes r1 = floor((r + gamma2 - 1) / alpha).
    let r1 = div_floor(r + gamma2 - 1, alpha);
    let r0 = r - r1 * alpha;
    // r1 never exceeds m = (q - 1) / alpha; when it equals it, r - r0 is
    // q - 1 and the standard's special case applies. `edge` is all ones
    // exactly then.
    let m = (Q - 1) / alpha;
    let edge = !((r1 - m) >> 31);
    (r1 & !edge, r0 - (edge & 1))
}

/// FIPS 204 Algorithm 37, `HighBits`.
#[inline(always)]
pub fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// FIPS 204 Algorithm 38, `LowBits`, as a signed integer.
#[inline(always)]
pub fn low_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

/// FIPS 204 Algorithm 39, `MakeHint`: 1 when adding `z` to `r` changes the
/// high bits of `r`, else 0, for `z` and `r` in `[0, q)`. No branch on the
/// values.
#[inline(always)]
pub fn make_hint(z: i32, r: i32, gamma2: i32) -> i32 {
    let d = high_bits(r, gamma2) ^ high_bits(add(r, z), gamma2);
    ((d | -d) >> 31) & 1
}

/// FIPS 204 Algorithm 40, `UseHint`, for `r` in `[0, q)` and `h` in
/// `{0, 1}`. Used by verification, on public values only.
pub fn use_hint(h: i32, r: i32, gamma2: i32) -> i32 {
    let m = (Q - 1) / (2 * gamma2);
    let (r1, r0) = decompose(r, gamma2);
    match (h, r0 > 0) {
        (1, true) => (r1 + 1) % m,
        (1, false) => (r1 + m - 1) % m,
        _ => r1,
    }
}

/// `|c|` for a coefficient `c` in `[0, q)` read as its centered
/// representative in `(-(q-1)/2, (q-1)/2]`: the infinity norm's term.
/// No branch on the value.
#[inline(always)]
pub fn centered_abs(c: i32) -> i32 {
    let v = c - ((((Q - 1) / 2 - c) >> 31) & Q);
    (v ^ (v >> 31)) - (v >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 204 Appendix B, extracted from the standard's text by script,
    /// not retyped.
    const APPENDIX_B: [i32; N] = [
        0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485,
        2682288, 2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802,
        4855975, 7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319,
        2815639, 2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
        394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347,
        7562881, 4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317,
        2917338, 1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610,
        5258977, 8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
        1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034,
        1987814, 5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690,
        3482206, 4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756,
        2925816, 3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
        348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997,
        5720892, 6924527, 2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111,
        4423672, 6084020, 5095502, 4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822,
        4423473, 4620952, 6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
        4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099,
        1239911, 4541938, 3195676, 2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018,
        7025525, 613238, 7070156, 6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539,
        7561656, 6201452, 6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
        6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997,
        2647994, 3009748, 5767564, 4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229,
        1665318, 2028038, 1163598, 5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880,
        545376, 7609976, 3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
        6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710, 8077412, 3531229,
        4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
    ];

    #[test]
    fn zetas_are_appendix_bs() {
        assert_eq!(ZETAS, APPENDIX_B);
    }

    #[test]
    fn reduce_agrees_with_the_remainder_operator() {
        let q = Q as u64;
        let edges = [
            0,
            1,
            q - 1,
            q,
            q + 1,
            2 * q - 1,
            2 * q,
            (q - 1) * (q - 1),
            (q - 1) * (q - 1) + 3 * (q - 1),
            (1 << 48) - 1,
        ];
        for a in edges {
            assert_eq!(reduce(a) as u64, a % q, "a = {a}");
        }
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let a = x & ((1 << 48) - 1);
            assert_eq!(reduce(a) as u64, a % q, "a = {a}");
        }
    }

    #[test]
    fn add_sub_and_from_signed_stay_in_range() {
        let q = Q;
        for (a, b) in [(0, 0), (q - 1, q - 1), (0, q - 1), (q - 1, 0), (1, q - 1)] {
            assert_eq!(add(a, b), (a + b) % q);
            assert_eq!(sub(a, b), (a - b).rem_euclid(q));
        }
        for v in [-q + 1, -8192, -1, 0, 1, 4096, q - 1] {
            assert_eq!(from_signed(v), v.rem_euclid(q), "v = {v}");
        }
    }

    #[test]
    fn ntt_inverse_undoes_ntt() {
        let mut w = [0i32; N];
        let mut x: u32 = 12345;
        for c in w.iter_mut() {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *c = (x % Q as u32) as i32;
        }
        let original = w;
        ntt(&mut w);
        assert_ne!(w, original, "the NTT must change a random polynomial");
        ntt_inverse(&mut w);
        assert_eq!(w, original);
    }

    /// The NTT turns multiplication in `Z_q[X]/(X^256 + 1)` into a
    /// coefficient-wise product: X * X^255 = X^256 = -1.
    #[test]
    fn the_ntt_multiplies_in_the_negacyclic_ring() {
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        a[1] = 1;
        b[255] = 1;
        ntt(&mut a);
        ntt(&mut b);
        let mut c = [0i32; N];
        multiply_add_ntt(&mut c, &a, &b);
        ntt_inverse(&mut c);
        let mut want = [0i32; N];
        want[0] = Q - 1;
        assert_eq!(c, want);
    }

    #[test]
    fn power2round_splits_every_coefficient_as_the_standard_says() {
        let half = 1 << (crate::D - 1);
        for r in (0..Q)
            .step_by(97)
            .chain([0, 1, 4095, 4096, 4097, 8191, 8192, Q - 1])
        {
            let (r1, r0) = power2round(r);
            assert_eq!(r1 * (1 << crate::D) + r0, r, "r = {r}");
            assert!(-half < r0 && r0 <= half, "r = {r}: r0 = {r0}");
            assert!(
                (0..1 << 10).contains(&r1),
                "r = {r}: r1 = {r1} needs 10 bits"
            );
        }
    }

    /// The standard's own Decompose, written with `%` and `/` as FIPS 204
    /// states it, which is what [`decompose`] is checked against.
    fn standard_decompose(r: i32, gamma2: i32) -> (i32, i32) {
        let alpha = 2 * gamma2;
        let mut r0 = r % alpha;
        if r0 > gamma2 {
            r0 -= alpha;
        }
        if r - r0 == Q - 1 {
            return (0, r0 - 1);
        }
        ((r - r0) / alpha, r0)
    }

    /// The standard's own Decompose, with `%` and `/`, for every `r` in
    /// `[0, q)` at both values of gamma2: the branch-free one must agree
    /// everywhere, the special case at `r1 = m` included.
    #[test]
    fn decompose_agrees_with_the_standard_for_every_r() {
        for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
            every_r_agrees(gamma2);
        }
    }

    /// Every `r` in `[0, q)` at one `gamma2`.
    fn every_r_agrees(gamma2: i32) {
        for r in 0..Q {
            assert_eq!(
                decompose(r, gamma2),
                standard_decompose(r, gamma2),
                "gamma2 {gamma2}, r {r}"
            );
        }
    }

    #[test]
    fn centered_abs_is_the_distance_to_zero_mod_q() {
        for (c, want) in [
            (0, 0),
            (1, 1),
            (Q - 1, 1),
            ((Q - 1) / 2, (Q - 1) / 2),
            ((Q + 1) / 2, (Q - 1) / 2),
        ] {
            assert_eq!(centered_abs(c), want, "c = {c}");
        }
    }
}
