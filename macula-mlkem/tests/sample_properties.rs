//! Structural checks on sampling, ahead of any vector.
use macula_mlkem::poly::Q;
use macula_mlkem::sample::{prf, sample_ntt, sample_poly_cbd};

#[test]
fn sample_ntt_stays_in_range_and_is_deterministic() {
    for byte in 0u8..8 {
        let seed = [byte; 34];
        let a = sample_ntt(&seed);
        assert!(
            a.iter().all(|&c| c >= 0 && c < Q as i16),
            "seed {byte}: a coefficient left [0, q)"
        );
        assert_eq!(a, sample_ntt(&seed), "seed {byte}: not deterministic");
    }
}

/// Different seeds must give different polynomials. A `sample_ntt` that
/// ignored its seed would pass the range and determinism checks above.
#[test]
fn sample_ntt_depends_on_its_seed() {
    let a = sample_ntt(&[1u8; 34]);
    let b = sample_ntt(&[2u8; 34]);
    assert_ne!(a, b);

    // And on the trailing index bytes specifically, which is how the
    // matrix A gets distinct entries from one rho.
    let mut s1 = [7u8; 34];
    let mut s2 = [7u8; 34];
    s1[32] = 0;
    s1[33] = 1;
    s2[32] = 1;
    s2[33] = 0;
    assert_ne!(
        sample_ntt(&s1),
        sample_ntt(&s2),
        "i and j must not be interchangeable"
    );
}

/// A coefficient folded to the centre of the ring: values above q/2 wrap
/// to negative, so the support comes back as [-eta, eta].
fn centred(c: i16) -> i32 {
    if c as i32 > Q / 2 {
        c as i32 - Q
    } else {
        c as i32
    }
}

/// One drawn polynomial, every coefficient checked to lie in [-eta, eta].
fn assert_cbd_is_centred(eta: usize, byte: u8) {
    let f = sample_poly_cbd(eta, &prf(eta, &[byte; 32], 0));
    for &c in f.iter() {
        assert!(
            centred(c).abs() <= eta as i32,
            "eta = {eta}: coefficient {c} is outside [-{eta}, {eta}]"
        );
    }
}

/// The centred binomial distribution is supported on [-eta, eta], which
/// after folding is [0, eta] together with [q-eta, q).
#[test]
fn sample_poly_cbd_is_supported_on_the_centred_binomial_range() {
    for eta in [2usize, 3] {
        for byte in 0u8..4 {
            assert_cbd_is_centred(eta, byte);
        }
    }
}

/// Zero bits give zero coefficients: x and y are both 0 for every
/// coefficient, so the difference is 0. A cheap check that the windows
/// are being read at all.
#[test]
fn sample_poly_cbd_of_all_zero_bytes_is_the_zero_polynomial() {
    for eta in [2usize, 3] {
        assert_eq!(sample_poly_cbd(eta, &vec![0u8; 64 * eta]), [0i16; 256]);
    }
}

/// All-ones gives x = y = eta for every coefficient, so every difference
/// is 0 too. Together with the previous test this pins that BOTH windows
/// are read: an implementation reading one window twice would also give
/// zero here, but would fail the distribution test above.
#[test]
fn sample_poly_cbd_of_all_one_bytes_is_the_zero_polynomial() {
    for eta in [2usize, 3] {
        assert_eq!(sample_poly_cbd(eta, &vec![0xffu8; 64 * eta]), [0i16; 256]);
    }
}

#[test]
fn prf_length_and_determinism() {
    for eta in [2usize, 3] {
        let a = prf(eta, &[5u8; 32], 3);
        assert_eq!(a.len(), 64 * eta);
        assert_eq!(a, prf(eta, &[5u8; 32], 3));
        assert_ne!(a, prf(eta, &[5u8; 32], 4), "the counter byte must matter");
        assert_ne!(a, prf(eta, &[6u8; 32], 3), "the seed must matter");
    }
}
