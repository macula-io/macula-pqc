//! ML-KEM against NIST's own ACVP vectors, byte-exact.
//!
//! ⚠ THIS FILE IS THE MOST DANGEROUS ARTEFACT IN THE CRATE. A vector
//! harness that silently passes everything would make every subsequent
//! claim green and meaningless. So its own failure path is tested:
//! `the_harness_fails_loudly_on_a_mismatch` feeds `compare` a deliberate
//! mismatch and asserts it panics with a message naming the group, the
//! test id and the operation.
//!
//! ⚠ AND A RED MUST LOCALISE. The failure will arrive days after the code
//! was written, so "ML-KEM is wrong" is not good enough: every assertion
//! goes through `compare`, which names the parameter set, the `tcId` and
//! the operation, and shows byte lengths before the values.

use std::collections::BTreeMap;
use std::path::PathBuf;

use macula_mlkem::{ParameterSet, ML_KEM_1024, ML_KEM_512, ML_KEM_768};
use serde_json::Value;

const KEYGEN: &str = "ML-KEM-keyGen-FIPS203";
const ENCAP_DECAP: &str = "ML-KEM-encapDecap-FIPS203";

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

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The single comparison every assertion goes through, so a red always
/// localises and always looks the same.
///
/// Panics with the parameter set, the `tcId` and the operation named. The
/// byte lengths come before the values because a length mismatch is a
/// different fault from a content mismatch and should be visible without
/// reading two thousand hex characters.
fn compare(set: &str, tc_id: u64, op: &str, got: &[u8], want: &[u8]) {
    assert_eq!(
        got.len(),
        want.len(),
        "{set} tcId {tc_id} {op}: LENGTH differs, got {} bytes, expected {}",
        got.len(),
        want.len()
    );
    assert_eq!(
        hex_of(got),
        hex_of(want),
        "{set} tcId {tc_id} {op}: {} bytes, content differs",
        got.len()
    );
}

fn param(name: &str) -> ParameterSet {
    match name {
        "ML-KEM-512" => ML_KEM_512,
        "ML-KEM-768" => ML_KEM_768,
        "ML-KEM-1024" => ML_KEM_1024,
        other => panic!("unknown parameter set in the vectors: {other}"),
    }
}

/// Expected results by tcId, as the whole JSON object so each caller
/// reads the fields it needs.
fn expected(dir: &str) -> BTreeMap<u64, Value> {
    let e = vectors(dir, "expectedResults.json");
    let mut out = BTreeMap::new();
    for g in e["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            out.insert(t["tcId"].as_u64().unwrap(), t.clone());
        }
    }
    out
}

/// One test's `reason`, when the projection carries one.
fn add_reason(out: &mut BTreeMap<u64, String>, t: &Value) {
    if let Some(r) = t.get("reason").and_then(|v| v.as_str()) {
        out.insert(t["tcId"].as_u64().unwrap(), r.to_string());
    }
}

/// The `reason` labels live ONLY in internalProjection, not in prompt or
/// expectedResults. A harness built from the other two gets the rejection
/// cases but cannot tell which they are, and would not notice them all
/// passing for the wrong reason.
fn reasons(dir: &str) -> BTreeMap<u64, String> {
    let p = vectors(dir, "internalProjection.json");
    let mut out = BTreeMap::new();
    for g in p["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            add_reason(&mut out, t);
        }
    }
    out
}

/// Whether a test's vector labels it an implicit-rejection case.
fn is_modified_ciphertext(reasons: &BTreeMap<u64, String>, t: &Value) -> bool {
    reasons
        .get(&t["tcId"].as_u64().unwrap())
        .map(String::as_str)
        == Some("modified ciphertext")
}

// ---------------------------------------------------------------------
// The shape of the vector files, asserted before anything is run
// ---------------------------------------------------------------------

/// ⛔ A vector file that changes shape must fail LOUDLY rather than
/// silently covering less. A harness that quietly ran 3 of 5 rejection
/// cases is the exact failure this crate exists to be immune to.
#[test]
fn keygen_vector_file_has_the_expected_shape() {
    let p = vectors(KEYGEN, "prompt.json");
    let groups = p["testGroups"].as_array().unwrap();
    assert_eq!(groups.len(), 3, "one keyGen group per parameter set");
    for g in groups {
        assert_eq!(g["testType"], "AFT");
        assert_eq!(
            g["tests"].as_array().unwrap().len(),
            25,
            "{}: keyGen AFT count",
            g["parameterSet"]
        );
    }
}

/// ⛔ Exactly half the decapsulation cases must be implicit-rejection
/// cases. If a later vector file has fewer, this fails rather than the
/// suite quietly testing the rejection path less.
fn assert_decapsulation_shape(set: &str, tests: &[Value], reasons: &BTreeMap<u64, String>) {
    assert_eq!(tests.len(), 10, "{set} decapsulation VAL count");
    let modified = tests
        .iter()
        .filter(|t| is_modified_ciphertext(reasons, t))
        .count();
    assert_eq!(
        modified, 5,
        "{set}: expected exactly 5 of 10 decapsulation cases to carry \
         reason \"modified ciphertext\""
    );
}

#[test]
fn encap_decap_vector_file_has_the_expected_shape() {
    let p = vectors(ENCAP_DECAP, "prompt.json");
    let reasons = reasons(ENCAP_DECAP);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();

    for g in p["testGroups"].as_array().unwrap() {
        let function = g["function"].as_str().unwrap();
        let set = g["parameterSet"].as_str().unwrap();
        let tests = g["tests"].as_array().unwrap();
        *seen.entry(function.to_string()).or_default() += 1;

        match function {
            "encapsulation" => assert_eq!(tests.len(), 25, "{set} encapsulation AFT count"),
            "decapsulation" => assert_decapsulation_shape(set, tests, &reasons),
            "encapsulationKeyCheck" | "decapsulationKeyCheck" => {
                assert_eq!(tests.len(), 10, "{set} {function} count")
            }
            other => panic!("unhandled function in the vectors: {other}"),
        }
    }
    assert_eq!(
        seen.get("encapsulation"),
        Some(&3),
        "one encap group per set"
    );
    assert_eq!(
        seen.get("decapsulation"),
        Some(&3),
        "one decap group per set"
    );
}

// ---------------------------------------------------------------------
// The harness's own failure path
// ---------------------------------------------------------------------

/// ⛔ PROVES THE HARNESS CAN FAIL, and that it says something useful when
/// it does. Without this, a harness that compared nothing would look
/// exactly like a correct implementation.
#[test]
fn the_harness_fails_loudly_on_a_mismatch() {
    let content = std::panic::catch_unwind(|| {
        compare(
            "ML-KEM-1024",
            42,
            "encapsulation ciphertext",
            &[1, 2, 3],
            &[1, 2, 4],
        );
    })
    .unwrap_err();
    let msg = panic_message(&content);
    for needle in [
        "ML-KEM-1024",
        "42",
        "encapsulation ciphertext",
        "content differs",
    ] {
        assert!(
            msg.contains(needle),
            "a mismatch message must name {needle}: {msg}"
        );
    }

    let length = std::panic::catch_unwind(|| {
        compare(
            "ML-KEM-768",
            7,
            "decapsulation shared secret",
            &[1, 2],
            &[1, 2, 3],
        );
    })
    .unwrap_err();
    let msg = panic_message(&length);
    assert!(
        msg.contains("LENGTH differs"),
        "a length mismatch must say so: {msg}"
    );
    assert!(
        msg.contains("ML-KEM-768") && msg.contains('7'),
        "and localise: {msg}"
    );
}

fn panic_message(e: &Box<dyn std::any::Any + Send>) -> String {
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// A positive control for the same function: matching values must NOT
/// panic. A `compare` that always panicked would pass the test above.
#[test]
fn the_harness_accepts_a_match() {
    compare(
        "ML-KEM-1024",
        1,
        "encapsulation ciphertext",
        &[9, 9, 9],
        &[9, 9, 9],
    );
}

// ---------------------------------------------------------------------
// The operations. Red until ML-KEM is implemented.
// ---------------------------------------------------------------------

#[test]
fn key_gen_matches_acvp() {
    let exp = expected(KEYGEN);
    let p = vectors(KEYGEN, "prompt.json");
    for g in p["testGroups"].as_array().unwrap() {
        let set = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let d: [u8; 32] = hex(t["d"].as_str().unwrap()).try_into().unwrap();
            let z: [u8; 32] = hex(t["z"].as_str().unwrap()).try_into().unwrap();
            let (ek, dk) = macula_mlkem::internal::key_gen(param(set), &d, &z);
            let want = &exp[&tc];
            compare(
                set,
                tc,
                "encapsulation key",
                &ek,
                &hex(want["ek"].as_str().unwrap()),
            );
            compare(
                set,
                tc,
                "decapsulation key",
                &dk,
                &hex(want["dk"].as_str().unwrap()),
            );
        }
    }
}

#[test]
fn encaps_matches_acvp() {
    let exp = expected(ENCAP_DECAP);
    let p = vectors(ENCAP_DECAP, "prompt.json");
    for g in p["testGroups"].as_array().unwrap() {
        if g["function"] != "encapsulation" {
            continue;
        }
        let set = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let ek = hex(t["ek"].as_str().unwrap());
            let m: [u8; 32] = hex(t["m"].as_str().unwrap()).try_into().unwrap();
            let (c, k) = macula_mlkem::internal::encaps(param(set), &ek, &m)
                .unwrap_or_else(|e| panic!("{set} tcId {tc} encapsulation refused: {e:?}"));
            let want = &exp[&tc];
            compare(set, tc, "ciphertext", &c, &hex(want["c"].as_str().unwrap()));
            compare(
                set,
                tc,
                "shared secret",
                &k[..],
                &hex(want["k"].as_str().unwrap()),
            );
        }
    }
}

/// One decapsulation case: assert its shared secret against the expected
/// `k`, and return 1 when the vector labels it an implicit rejection.
fn check_decaps_case(
    set: &str,
    exp: &BTreeMap<u64, Value>,
    reasons: &BTreeMap<u64, String>,
    t: &Value,
) -> usize {
    let tc = t["tcId"].as_u64().unwrap();
    let dk = hex(t["dk"].as_str().unwrap());
    let c = hex(t["c"].as_str().unwrap());
    let reason = reasons.get(&tc).map(String::as_str).unwrap_or("unlabelled");
    let k = macula_mlkem::decaps(param(set), &dk, &c).unwrap_or_else(|e| {
        panic!(
            "{set} tcId {tc} ({reason}): decapsulation returned an ERROR ({e:?}). \
             FIPS 203 returns a pseudorandom secret on a modified ciphertext, \
             never an error."
        )
    });
    let want = &exp[&tc];
    compare(
        set,
        tc,
        &format!("shared secret [{reason}]"),
        &k[..],
        &hex(want["k"].as_str().unwrap()),
    );
    usize::from(reason == "modified ciphertext")
}

/// ⛔ THE IMPLICIT-REJECTION CASES ARE ASSERTED AGAINST THE EXPECTED `k`,
/// BY LABEL, not by "decapsulation failed". FIPS 203 returns a
/// deterministic pseudorandom secret for a modified ciphertext, so an
/// implementation that returns an error instead passes every happy-path
/// vector and fails exactly these.
#[test]
fn decaps_matches_acvp_including_implicit_rejection() {
    let exp = expected(ENCAP_DECAP);
    let reasons = reasons(ENCAP_DECAP);
    let p = vectors(ENCAP_DECAP, "prompt.json");
    let mut rejections = 0usize;

    for g in p["testGroups"].as_array().unwrap() {
        if g["function"] != "decapsulation" {
            continue;
        }
        let set = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            rejections += check_decaps_case(set, &exp, &reasons, t);
        }
    }
    assert_eq!(
        rejections, 15,
        "5 implicit-rejection cases per parameter set, 3 sets"
    );
}

/// The key check the vector's `function` names, on the key it carries.
fn key_check(function: &str, set: &str, t: &Value) -> bool {
    if function == "encapsulationKeyCheck" {
        return macula_mlkem::encaps_key_valid(param(set), &hex(t["ek"].as_str().unwrap()));
    }
    macula_mlkem::decaps_key_valid(param(set), &hex(t["dk"].as_str().unwrap()))
}

#[test]
fn key_checks_match_acvp() {
    let exp = expected(ENCAP_DECAP);
    let p = vectors(ENCAP_DECAP, "prompt.json");
    for g in p["testGroups"].as_array().unwrap() {
        let function = g["function"].as_str().unwrap();
        if !function.ends_with("KeyCheck") {
            continue;
        }
        let set = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let want = exp[&tc]["testPassed"].as_bool().unwrap();
            let got = key_check(function, set, t);
            assert_eq!(got, want, "{set} tcId {tc} {function}");
        }
    }
}
