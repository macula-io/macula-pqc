//! Structural checks on encoding and compression, ahead of any vector, so
//! a later ACVP red localises here rather than to sampling or the KEM.
use macula_mlkem::encode::{byte_decode, byte_encode, compress, decompress};
use macula_mlkem::poly::Q;

fn lcg(seed: &mut u64, bound: u32) -> i16 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    ((*seed >> 33) % bound as u64) as i16
}

/// ByteEncode and ByteDecode must be exact inverses at every width
/// ML-KEM uses.
#[test]
fn encode_then_decode_is_the_identity() {
    let mut seed = 11u64;
    for d in [1usize, 4, 5, 10, 11, 12] {
        let bound = if d == 12 { Q as u32 } else { 1u32 << d };
        for _ in 0..16 {
            let mut f = [0i16; 256];
            fill_from_lcg(&mut f, &mut seed, bound);
            // A DIRTY buffer: the encoder ORs bits in, so it must clear
            // what the caller's buffer held before.
            let mut bytes = vec![0xaau8; 32 * d];
            byte_encode(d, &f, &mut bytes);
            assert_eq!(byte_decode(d, &bytes), f, "d = {d}");
        }
    }
}

/// Fill a polynomial with values below `bound` from the test generator.
fn fill_from_lcg(f: &mut [i16; 256], seed: &mut u64, bound: u32) {
    for c in f.iter_mut() {
        *c = lcg(seed, bound);
    }
}

/// Compression is lossy by design, so the round trip must land within
/// the error bound FIPS 203 states rather than return the input.
#[test]
fn decompress_of_compress_stays_within_the_stated_error_bound() {
    for d in [1usize, 4, 5, 10, 11] {
        let bound = (Q as f64 / (1u32 << (d + 1)) as f64).round() as i32;
        for x in 0..Q as i16 {
            let back = decompress(d, compress(d, x)) as i32;
            // The ring wraps: an error of q-1 is an error of 1, so the
            // smaller of the two directions is the real error.
            let err = (back - x as i32).abs();
            let err = err.min(Q - err);
            assert!(
                err <= bound,
                "d = {d}, x = {x}: error {err} exceeds the bound {bound}"
            );
        }
    }
}

/// Compress_d must land in [0, 2^d).
#[test]
fn compress_lands_in_range() {
    for d in [1usize, 4, 5, 10, 11] {
        for x in 0..Q as i16 {
            let c = compress(d, x);
            assert!(
                c >= 0 && (c as u32) < (1u32 << d),
                "d = {d}, x = {x} gave {c}"
            );
        }
    }
}

/// `compress` must equal the FIPS 203 rounding formula for EVERY input at
/// every width. The reference below divides by q, which the implementation
/// must not do on secret data; this pins that the division-free form gives
/// identical answers everywhere, not just on a sample.
#[test]
fn compress_equals_the_division_formula_exhaustively() {
    for d in [1usize, 4, 5, 10, 11] {
        for x in 0..Q as i16 {
            let reference = ((((x as u64) << d) + (Q as u64) / 2) / Q as u64) & ((1u64 << d) - 1);
            assert_eq!(compress(d, x) as u64, reference, "d = {d}, x = {x}");
        }
    }
}

/// ByteDecode_12 reduces every 12-bit value mod q, including the 767
/// values in [q, 4096) that a malformed key can carry.
#[test]
fn byte_decode_12_reduces_every_12_bit_value() {
    for chunk in 0..16u32 {
        let mut f = [0i16; 256];
        let mut raw = [0u32; 256];
        for (i, r) in raw.iter_mut().enumerate() {
            *r = chunk * 256 + i as u32;
        }
        // Pack the raw 12-bit values, bypassing byte_encode's range.
        let mut bytes = vec![0u8; 384];
        let mut bit = 0usize;
        for &v in raw.iter() {
            pack_12_bits(&mut bytes, v, &mut bit);
        }
        f.copy_from_slice(&byte_decode(12, &bytes));
        for (i, &c) in f.iter().enumerate() {
            assert_eq!(c as u32, raw[i] % Q as u32, "raw value {}", raw[i]);
        }
    }
}

/// Write `v` as twelve little-endian bits from `bit` on, ORed into `bytes`
/// at whatever byte boundaries they land on.
fn pack_12_bits(bytes: &mut [u8], v: u32, bit: &mut usize) {
    for b in 0..12 {
        bytes[*bit / 8] |= (((v >> b) & 1) as u8) << (*bit % 8);
        *bit += 1;
    }
}
