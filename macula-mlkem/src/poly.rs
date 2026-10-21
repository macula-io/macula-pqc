//! Arithmetic in `Z_q[X]/(X^256 + 1)` for `q = 3329`, per FIPS 203.
//!
//! ⚠ No secret-dependent branch or index is written here by construction:
//! reduction is Barrett, comparisons are arithmetic, and every loop bound
//! is a compile-time constant. That is a statement about the code's shape
//! and **not a measurement**; see the crate docs.

/// FIPS 203 section 2.3: the modulus.
pub const Q: i32 = 3329;
/// The degree of the ring.
pub const N: usize = 256;

/// A polynomial, coefficients in `[0, q)`.
pub type Poly = [i16; N];

/// Barrett reduction to `[0, q)`. No branch on the value.
///
/// ⚠ The intermediate is i64 ON PURPOSE. `V * a` with `a` near `q^2`
/// (which is what a coefficient product is) overflows i32 by two orders
/// of magnitude, and in a release build that wraps silently into a wrong
/// result.
#[inline(always)]
pub fn reduce(a: i32) -> i16 {
    const V: i64 = (1 << 26) / Q as i64;
    let a64 = a as i64;
    let t = ((V * a64 + (1 << 25)) >> 26) * Q as i64;
    let r = a64 - t;
    // r is in (-q, q); fold the negative case without a branch.
    let r = r + ((r >> 63) & Q as i64);
    r as i16
}

/// `a * b mod q`, for `a` and `b` in `[0, q)`, by [`reduce`].
#[inline(always)]
pub fn mul(a: i16, b: i16) -> i16 {
    reduce(a as i32 * b as i32)
}

/// `a + b mod q`, for `a` and `b` in `[0, q)`, subtracting `q` under a
/// mask rather than a branch.
#[inline(always)]
pub fn add(a: i16, b: i16) -> i16 {
    let s = a as i32 + b as i32;
    (s - ((((Q - 1 - s) >> 31) & 1) * Q)) as i16
}

/// `a - b mod q`, for `a` and `b` in `[0, q)`, adding `q` under a mask
/// rather than a branch.
#[inline(always)]
pub fn sub(a: i16, b: i16) -> i16 {
    let d = a as i32 - b as i32;
    (d + ((d >> 31) & Q)) as i16
}

/// `zeta^BitRev7(i)` for i in 0..128, built at COMPILE TIME rather than
/// transcribed.
///
/// ⚠ A hand-copied table would be a second place for the contract to
/// live, and a single mistyped digit produces a coherent-looking
/// implementation that fails every vector with no hint where. Computing
/// it from the definition removes that entirely.
pub const ZETAS: [i16; 128] = build_zetas();

const fn build_zetas() -> [i16; 128] {
    let mut out = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = pow17(bit_rev7(i)) as i16;
        i += 1;
    }
    out
}

/// The seven-bit reversal of `i`, FIPS 203 Algorithm 9's BitRev7.
const fn bit_rev7(i: usize) -> usize {
    let mut r = 0usize;
    let mut b = 0;
    while b < 7 {
        r |= ((i >> b) & 1) << (6 - b);
        b += 1;
    }
    r
}

/// `17^r mod q` by square and multiply.
const fn pow17(r: usize) -> i32 {
    let mut acc: i32 = 1;
    let mut base: i32 = 17;
    let mut e = r;
    while e > 0 {
        if e & 1 == 1 {
            acc = (acc * base) % Q;
        }
        base = (base * base) % Q;
        e >>= 1;
    }
    acc
}

/// FIPS 203 Algorithm 9: NTT.
pub fn ntt(f: &mut Poly) {
    let mut i = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[i];
            i += 1;
            butterfly(f, start, len, zeta);
            start += 2 * len;
        }
        len /= 2;
    }
}

/// One row of the forward butterfly: the `j`/`j + len` pair in a block.
#[inline(always)]
fn butterfly(f: &mut Poly, start: usize, len: usize, zeta: i16) {
    for j in start..start + len {
        let t = mul(zeta, f[j + len]);
        f[j + len] = sub(f[j], t);
        f[j] = add(f[j], t);
    }
}

/// FIPS 203 Algorithm 10: inverse NTT, including the final scaling by
/// `128^-1 mod q = 3303`.
pub fn intt(f: &mut Poly) {
    let mut i = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[i];
            i = i.wrapping_sub(1);
            inverse_butterfly(f, start, len, zeta);
            start += 2 * len;
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = mul(*c, 3303);
    }
}

/// One row of the inverse butterfly: the `j`/`j + len` pair in a block.
#[inline(always)]
fn inverse_butterfly(f: &mut Poly, start: usize, len: usize, zeta: i16) {
    for j in start..start + len {
        let t = f[j];
        f[j] = add(t, f[j + len]);
        f[j + len] = mul(zeta, sub(f[j + len], t));
    }
}

/// FIPS 203 Algorithm 12: BaseCaseMultiply.
#[inline]
fn base_case_multiply(a0: i16, a1: i16, b0: i16, b1: i16, gamma: i16) -> (i16, i16) {
    let c0 = add(mul(a0, b0), mul(mul(a1, b1), gamma));
    let c1 = add(mul(a0, b1), mul(a1, b0));
    (c0, c1)
}

/// FIPS 203 Algorithm 11: MultiplyNTTs.
pub fn multiply_ntts(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i16; N];
    for i in 0..128 {
        // gamma = zeta^(2*BitRev7(i)+1); ZETAS[i] is zeta^BitRev7(i), so
        // gamma = ZETAS[i]^2 * zeta, and FIPS tabulates it as such.
        let gamma = mul(ZETAS[i], ZETAS[i]);
        let gamma = mul(gamma, 17);
        let (c0, c1) = base_case_multiply(a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], gamma);
        out[2 * i] = c0;
        out[2 * i + 1] = c1;
    }
    out
}

/// [`add`] coefficient by coefficient.
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i16; N];
    for i in 0..N {
        out[i] = add(a[i], b[i]);
    }
    out
}

/// [`sub`] coefficient by coefficient.
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i16; N];
    for i in 0..N {
        out[i] = sub(a[i], b[i]);
    }
    out
}
