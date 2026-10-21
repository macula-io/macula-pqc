//! Structural checks on the ring arithmetic, before any vector is
//! involved. These cannot prove ML-KEM correct; they localise a fault to
//! the NTT rather than to sampling or encoding when a vector goes red.
use macula_mlkem::poly::{intt, multiply_ntts, ntt, reduce, Q};

fn lcg(seed: &mut u64) -> i16 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    ((*seed >> 33) % Q as u64) as i16
}

#[test]
fn ntt_then_inverse_is_the_identity() {
    let mut seed = 42u64;
    for _ in 0..64 {
        let mut f = [0i16; 256];
        for c in f.iter_mut() {
            *c = lcg(&mut seed);
        }
        let original = f;
        ntt(&mut f);
        intt(&mut f);
        assert_eq!(f, original);
    }
}

#[test]
fn reduce_lands_in_range() {
    for a in [0i32, 1, Q - 1, Q, Q + 1, 3328 * 3328, -1, -Q, -3328 * 3328] {
        let r = reduce(a);
        assert!((0..Q as i16).contains(&r), "reduce({a}) = {r}");
        assert_eq!(
            ((r as i32 - a) % Q + Q) % Q,
            0,
            "reduce({a}) changed the residue"
        );
    }
}

/// Schoolbook negacyclic multiplication, written independently of the NTT
/// so it can disagree with it. X^256 = -1, hence the subtraction when the
/// degree wraps.
fn schoolbook(a: &[i16; 256], b: &[i16; 256]) -> [i32; 256] {
    let mut want = [0i32; 256];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            add_term(&mut want, i + j, ai as i32 * bj as i32);
        }
    }
    want
}

/// Add `v` at degree `k` of a schoolbook product, subtracting it from
/// degree `k - 256` when the degree wraps.
fn add_term(want: &mut [i32; 256], k: usize, v: i32) {
    if k < 256 {
        want[k] += v;
        return;
    }
    want[k - 256] -= v;
}

/// Multiplication in the NTT domain must agree with schoolbook
/// multiplication in `Z_q[X]/(X^256+1)`.
#[test]
fn ntt_multiplication_agrees_with_schoolbook() {
    let mut seed = 7u64;
    for _ in 0..8 {
        let mut a = [0i16; 256];
        let mut b = [0i16; 256];
        for (x, y) in a.iter_mut().zip(b.iter_mut()) {
            *x = lcg(&mut seed);
            *y = lcg(&mut seed);
        }
        // schoolbook, negacyclic
        let want = schoolbook(&a, &b);
        let want: Vec<i16> = want.iter().map(|&v| (((v % Q) + Q) % Q) as i16).collect();

        let mut na = a;
        let mut nb = b;
        ntt(&mut na);
        ntt(&mut nb);
        let mut got = multiply_ntts(&na, &nb);
        intt(&mut got);
        assert_eq!(got.to_vec(), want);
    }
}
