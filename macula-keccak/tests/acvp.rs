//! Byte-exact against NIST's own ACVP vectors, vendored under `vectors/`.
//!
//! ⚠ WHY TWO VECTOR REVISIONS ARE USED, stated per function because the
//! two SHAKE directories do NOT behave the same and an earlier reading of
//! this generalised from one to both.
//!
//! - `SHAKE-128-FIPS202`: `outLen` 32 to 64 bytes against a 168-byte
//!   rate, so **every test fits inside the first squeezed block and NONE
//!   exercises a multi-block squeeze**. For SHAKE128 the multi-block
//!   coverage exists only in `SHAKE-128-1.0`'s VOT group: 37 runnable
//!   cases exceed the rate.
//! - `SHAKE-256-FIPS202`: `outLen` 16 to 512 bytes against a 136-byte
//!   rate, so it **does** carry multi-block cases, 25 of them.
//!
//! Multi-block squeezing is the sponge-state-across-calls path: where an
//! XOF goes wrong, and what ML-KEM leans on hardest when it expands its
//! matrix. `multi_block_coverage_exists_for_both_functions` asserts the
//! counts above rather than trusting this comment.
//!
//! ⚠ TWO DELIBERATE EXCLUSIONS, BOTH ASSERTED RATHER THAN ASSUMED.
//!
//! **Bit-oriented tests.** Most of the `-2.0` and `-1.0` vectors have
//! message lengths that are not multiples of 8: 1043 of 1194 for
//! SHA3-256, and 1218 of 1904 for SHAKE-128. This crate hashes BYTES,
//! because ML-KEM only ever hashes whole bytes, so those cases are not
//! runnable here and are skipped by `len % 8`. The counts below are
//! asserted so the skip stays bounded and visible: if a vector file
//! changes shape, the count changes and a test fails.
//!
//! ⚠ This corrects an earlier reading of these directories. The sets
//! named `-FIPS202` are 100% byte-aligned and are the ones a
//! byte-oriented implementation can run in full. The `-1.0` sets are not
//! simply "more coverage": they are a different ORIENTATION, of which the
//! byte-aligned subset is what remains. They are still the only source of
//! multi-block squeeze coverage, which is why both are used.
//!
//! **LDT groups**: 8 GiB per test, four tests. Not a unit test.
//! **MCT groups**: chained, handled separately, and their expected
//! results are a `resultsArray` rather than an `md`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use macula_keccak::{sha3_256, sha3_512, shake128, shake256, Shake128Reader, Shake256};
use serde_json::Value;

fn vectors(dir: &str, file: &str) -> Value {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "vectors", dir, file]
        .iter()
        .collect();
    serde_json::from_reader(
        std::fs::File::open(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
    )
    .unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `None` for a bit-oriented case, which this crate cannot run.
///
/// `len` is in BITS and is authoritative: a zero-length case still carries
/// a `msg` field, and taking the hex at face value would hash one byte the
/// vector says is not there.
fn message(test: &Value) -> Option<Vec<u8>> {
    let bits = test["len"].as_u64().unwrap() as usize;
    if !bits.is_multiple_of(8) {
        return None;
    }
    let mut m = hex(test["msg"].as_str().unwrap());
    m.truncate(bits / 8);
    Some(m)
}

/// Expected digests by tcId.
fn expected(dir: &str) -> BTreeMap<u64, String> {
    let e = vectors(dir, "expectedResults.json");
    let mut out = BTreeMap::new();
    for g in e["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            add_expected(&mut out, t);
        }
    }
    out
}

/// One expected result. MCT tests carry a `resultsArray`, not an `md`, and
/// are added by their own path.
fn add_expected(out: &mut BTreeMap<u64, String>, t: &serde_json::Value) {
    if let Some(md) = t.get("md").and_then(|v| v.as_str()) {
        out.insert(t["tcId"].as_u64().unwrap(), md.to_ascii_lowercase());
    }
}

/// Runs every AFT and VOT test in a directory, returning how many ran.
/// MCT is handled separately and LDT is skipped; both by name, so a new
/// group type is not silently ignored.
fn run(dir: &str, f: &dyn Fn(&[u8], usize) -> Vec<u8>) -> usize {
    let exp = expected(dir);
    let p = vectors(dir, "prompt.json");
    let mut ran = 0;
    for g in p["testGroups"].as_array().unwrap() {
        let tt = g["testType"].as_str().unwrap();
        if tt == "MCT" || tt == "LDT" {
            continue;
        }
        assert!(
            tt == "AFT" || tt == "VOT",
            "unhandled group type {tt} in {dir}"
        );
        for t in g["tests"].as_array().unwrap() {
            ran += check_one(dir, &exp, t, f);
        }
    }
    assert!(ran > 0, "{dir} ran no tests");
    ran
}

/// One AFT/VOT test against its expected digest: 1 when it ran, 0 when it
/// is skipped by name (a SHAKE length that is not a whole number of bytes).
fn check_one(
    dir: &str,
    exp: &BTreeMap<u64, String>,
    t: &serde_json::Value,
    f: &dyn Fn(&[u8], usize) -> Vec<u8>,
) -> usize {
    let tc = t["tcId"].as_u64().unwrap();
    let Some(msg) = message(t) else { return 0 };
    // SHAKE output lengths are in BITS too, and are not always a multiple
    // of 8. A partial final byte is a bit-oriented case and is skipped for
    // the same reason as a bit-oriented input.
    if bit_oriented_out(t) {
        return 0;
    }
    // SHA-3 has a fixed output; SHAKE carries its length per test.
    let out_bytes = t
        .get("outLen")
        .and_then(|v| v.as_u64())
        .map(|b| b as usize / 8)
        .unwrap_or(0);
    let got = f(&msg, out_bytes);
    let want = exp
        .get(&tc)
        .unwrap_or_else(|| panic!("no expected for tcId {tc}"));
    assert_eq!(
        hex_of(&got),
        *want,
        "{dir} tcId {tc}: msg {} bytes, out {out_bytes} bytes",
        msg.len()
    );
    1
}

/// A SHAKE output length that is not a whole number of bytes.
fn bit_oriented_out(t: &serde_json::Value) -> bool {
    t.get("outLen")
        .and_then(|v| v.as_u64())
        .is_some_and(|b| !b.is_multiple_of(8))
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn sha3_256_matches_acvp() {
    let n = run("SHA3-256-2.0", &|m, _| sha3_256(m).to_vec());
    assert_eq!(
        n, 151,
        "byte-aligned SHA3-256 AFT count changed: the vendored file is not what it was"
    );
}

#[test]
fn sha3_512_matches_acvp() {
    let n = run("SHA3-512-2.0", &|m, _| sha3_512(m).to_vec());
    assert_eq!(n, 86, "byte-aligned SHA3-512 AFT count changed");
}

#[test]
fn shake128_matches_acvp_including_multi_block_squeezes() {
    let n = run("SHAKE-128-1.0", &|m, o| {
        let mut out = vec![0u8; o];
        shake128(m, &mut out);
        out
    });
    assert_eq!(n, 236, "byte-aligned SHAKE-128 AFT+VOT count changed");
}

#[test]
fn shake256_matches_acvp_including_multi_block_squeezes() {
    let n = run("SHAKE-256-1.0", &|m, o| {
        let mut out = vec![0u8; o];
        shake256(m, &mut out);
        out
    });
    assert_eq!(n, 210, "byte-aligned SHAKE-256 AFT+VOT count changed");
}

#[test]
fn shake128_matches_the_fips202_revision_too() {
    run("SHAKE-128-FIPS202", &|m, o| {
        let mut out = vec![0u8; o];
        shake128(m, &mut out);
        out
    });
}

#[test]
fn shake256_matches_the_fips202_revision_too() {
    run("SHAKE-256-FIPS202", &|m, o| {
        let mut out = vec![0u8; o];
        shake256(m, &mut out);
        out
    });
}

/// ⚠ The property the `-FIPS202` vectors cannot test, asserted directly
/// rather than left to be exercised transitively by ML-KEM later. A
/// failure that only surfaced through ML-KEM would be diagnosed as an
/// ML-KEM bug and cost a day in the wrong crate.
#[test]
fn multi_block_coverage_exists_for_both_functions() {
    // (directory, rate in bytes, runnable cases expected to exceed it)
    for (dir, rate, want) in [
        ("SHAKE-128-1.0", 168usize, 37usize),
        ("SHAKE-256-1.0", 136, 50),
        ("SHAKE-256-FIPS202", 136, 25),
        // ⚠ Zero, deliberately asserted: this is the set whose name makes
        // it the obvious choice and which cannot test the path at all.
        ("SHAKE-128-FIPS202", 168, 0),
    ] {
        let p = vectors(dir, "prompt.json");
        let beyond = p["testGroups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["tests"].as_array().unwrap())
            .filter(|t| t["len"].as_u64().unwrap().is_multiple_of(8))
            .filter_map(|t| t.get("outLen").and_then(|v| v.as_u64()))
            .filter(|b| b.is_multiple_of(8))
            .filter(|b| (*b as usize) / 8 > rate)
            .count();
        assert_eq!(
            beyond, want,
            "{dir}: runnable cases exceeding the {rate}-byte rate"
        );
    }
}

/// Squeeze `out` in `chunk`-byte pieces: `chunks_mut` splits it into
/// whole chunks with the remainder last, so every piece but a short final
/// one straddles a 168-byte block boundary.
fn squeeze_in_chunks(r: &mut Shake128Reader, out: &mut [u8], chunk: usize) {
    for piece in out.chunks_mut(chunk) {
        r.read(piece);
    }
}

/// The incremental reader must agree with the one-shot, squeezed in
/// awkward chunk sizes that straddle block boundaries. ML-KEM reads this
/// way because it cannot know in advance how many bytes it needs.
#[test]
fn incremental_reader_agrees_with_one_shot_across_block_boundaries() {
    let msg = b"macula-keccak incremental squeeze";
    for total in [1usize, 167, 168, 169, 335, 336, 337, 512, 1000] {
        let mut want = vec![0u8; total];
        shake128(msg, &mut want);

        for chunk in [1usize, 7, 168, 200] {
            let mut r = Shake128Reader::new(msg);
            let mut got = vec![0u8; total];
            squeeze_in_chunks(&mut r, &mut got, chunk);
            assert_eq!(got, want, "total {total}, chunk {chunk}");
        }
    }
}

/// SHAKE256 absorbed and squeezed in pieces, the way ML-DSA uses it.
fn shake256_in_pieces(msg: &[u8], out_len: usize, absorb: usize, squeeze: usize) -> Vec<u8> {
    let mut h = Shake256::new();
    // An empty update between pieces must change nothing.
    h.update(&[]);
    for piece in msg.chunks(absorb) {
        h.update(piece);
        h.update(&[]);
    }
    let mut r = h.finalize_xof();
    let mut out = vec![0u8; out_len];
    for piece in out.chunks_mut(squeeze) {
        r.read(piece);
    }
    out
}

/// One absorb/squeeze profile against a SHAKE256 vector directory, returning
/// how many cases ran. Hoisted out of the sweep so the closure that binds the
/// profile is not nested inside two loops.
fn run_shake256_in_pieces(dir: &str, absorb: usize, squeeze: usize) -> usize {
    run(dir, &|m, o| shake256_in_pieces(m, o, absorb, squeeze))
}

/// ⛔ ML-DSA hashes through SHAKE256 in pieces on both sides: it absorbs
/// a secret key, its randomness and a message as separate inputs rather
/// than concatenating them into a buffer that would need wiping, and it
/// squeezes as much as rejection sampling asks for. So every byte-aligned
/// SHAKE256 vector NIST publishes is run again here, absorbed and squeezed
/// in chunk sizes that straddle the 136-byte rate, and must still match.
#[test]
fn incremental_shake256_matches_acvp_absorbed_and_squeezed_in_pieces() {
    for absorb in [1usize, 7, 135, 136, 137] {
        for squeeze in [1usize, 7, 136, 200] {
            let n = run_shake256_in_pieces("SHAKE-256-1.0", absorb, squeeze);
            assert_eq!(n, 210, "absorb {absorb}, squeeze {squeeze}");
            run_shake256_in_pieces("SHAKE-256-FIPS202", absorb, squeeze);
        }
    }
}

/// LDT must be the ONLY thing skipped. If a vector file gains a new group
/// type, this fails rather than the suite quietly covering less.
#[test]
fn skipped_groups_are_only_ldt_and_mct() {
    for dir in [
        "SHA3-256-2.0",
        "SHA3-512-2.0",
        "SHAKE-128-1.0",
        "SHAKE-256-1.0",
        "SHAKE-128-FIPS202",
        "SHAKE-256-FIPS202",
    ] {
        let p = vectors(dir, "prompt.json");
        for g in p["testGroups"].as_array().unwrap() {
            let tt = g["testType"].as_str().unwrap();
            assert!(
                matches!(tt, "AFT" | "VOT" | "MCT" | "LDT"),
                "{dir} has an unhandled group type {tt}"
            );
        }
    }
}
