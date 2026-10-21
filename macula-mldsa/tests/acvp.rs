//! ML-DSA against NIST's own ACVP vectors, byte-exact.
//!
//! ⚠ THIS FILE IS THE MOST DANGEROUS ARTEFACT IN THE CRATE. A vector
//! harness that silently passes everything would make every subsequent
//! claim green and meaningless. So its own failure path is tested:
//! `the_harness_fails_loudly_on_a_mismatch` feeds `compare` a deliberate
//! mismatch and asserts it panics with a message naming the parameter
//! set, the test id and the operation.
//!
//! ⚠ AND A RED MUST LOCALISE. Every assertion goes through `compare`,
//! which names the parameter set, the `tcId` and the operation, and shows
//! byte lengths before the values.
//!
//! ⛔ WHAT IS NOT RUN IS COUNTED, BESIDE ITS REASON. HashML-DSA groups are
//! excluded through one function, `hash_ml_dsa_excluded`, and the shape
//! tests assert exactly how many tests that removes from each file. A
//! vector file that grows a new kind of group fails here rather than
//! being skipped without anyone noticing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use macula_mldsa::{ParameterSet, ML_DSA_44, ML_DSA_65, ML_DSA_87};
use serde_json::Value;

const KEYGEN: &str = "ML-DSA-keyGen-FIPS204";
const SIGGEN: &str = "ML-DSA-sigGen-FIPS204";
const SIGGEN_TR1: &str = "ML-DSA-sigGen-FIPS204-tr1";
const SIGVER: &str = "ML-DSA-sigVer-FIPS204";

/// Why the HashML-DSA groups are not run. Kept beside the exclusion and
/// printed with the count, so the reason travels with the number.
const HASH_ML_DSA_REASON: &str = "HashML-DSA (FIPS 204 section 5.4) is not implemented: \
     pure ML-DSA only, no SHA-2 in this workspace";

/// The four ways NIST breaks a signature, and the one way it doesn't, as
/// labelled in the sigVer internalProjection.
const MODIFIED_MESSAGE: &str = "modified message";
const MODIFIED_COMMITMENT: &str = "modified signature - commitment";
const MODIFIED_Z: &str = "modified signature - z";
const MODIFIED_HINT: &str = "modified signature - hint";
const VALID: &str = "valid signature and message - signature should verify successfully";

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
/// reading nine thousand hex characters.
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
        "ML-DSA-44" => ML_DSA_44,
        "ML-DSA-65" => ML_DSA_65,
        "ML-DSA-87" => ML_DSA_87,
        other => panic!("unknown parameter set in the vectors: {other}"),
    }
}

fn groups(v: &Value) -> &Vec<Value> {
    v["testGroups"].as_array().unwrap()
}

fn tests(g: &Value) -> &Vec<Value> {
    g["tests"].as_array().unwrap()
}

/// Expected results by tcId, as the whole JSON object so each caller
/// reads the fields it needs.
fn expected(dir: &str) -> BTreeMap<u64, Value> {
    let e = vectors(dir, "expectedResults.json");
    let mut out = BTreeMap::new();
    for g in groups(&e) {
        for t in tests(g) {
            out.insert(t["tcId"].as_u64().unwrap(), t.clone());
        }
    }
    out
}

/// The `reason` labels live ONLY in internalProjection, not in prompt or
/// expectedResults. A harness built from the other two gets the negative
/// cases but cannot tell which is which, and would not notice all the
/// hint cases passing for the wrong reason.
fn reasons(dir: &str) -> BTreeMap<u64, String> {
    let p = vectors(dir, "internalProjection.json");
    let mut out = BTreeMap::new();
    for g in groups(&p) {
        for t in tests(g) {
            let tc = t["tcId"].as_u64().unwrap();
            let r = t["reason"]
                .as_str()
                .unwrap_or_else(|| panic!("tcId {tc} has no reason"));
            out.insert(tc, r.to_string());
        }
    }
    out
}

/// ⛔ THE ONE PLACE A GROUP IS LEFT OUT. True for a HashML-DSA group,
/// false for a pure one, and a panic for anything else: an interface or
/// pre-hash mode this harness has not been taught fails loudly instead of
/// being run as the wrong thing or skipped.
fn hash_ml_dsa_excluded(g: &Value) -> bool {
    match (
        g["signatureInterface"].as_str(),
        g.get("preHash").and_then(Value::as_str),
    ) {
        (Some("internal"), None) => false,
        (Some("external"), Some("pure")) => false,
        (Some("external"), Some("preHash")) => true,
        other => panic!(
            "tgId {}: a group kind this harness does not know: {other:?}",
            g["tgId"]
        ),
    }
}

/// The pure groups of a signing or verification file, and how many tests
/// the exclusion removed.
fn pure_groups(v: &Value) -> (Vec<&Value>, usize) {
    let mut run = Vec::new();
    let mut excluded = 0;
    for g in groups(v) {
        if hash_ml_dsa_excluded(g) {
            excluded += tests(g).len();
        } else {
            run.push(g);
        }
    }
    (run, excluded)
}

fn test_count(gs: &[&Value]) -> usize {
    gs.iter().map(|g| tests(g).len()).sum()
}

// ---------------------------------------------------------------------
// The shape of the vector files, asserted before anything is run
// ---------------------------------------------------------------------

/// ⛔ A vector file that changes shape must fail LOUDLY rather than
/// silently covering less.
#[test]
fn keygen_vector_file_has_the_expected_shape() {
    let p = vectors(KEYGEN, "prompt.json");
    let gs = groups(&p);
    assert_eq!(gs.len(), 3, "one keyGen group per parameter set");
    for g in gs {
        assert_eq!(g["testType"], "AFT");
        param(g["parameterSet"].as_str().unwrap());
        assert_eq!(
            tests(g).len(),
            25,
            "{}: keyGen AFT count",
            g["parameterSet"]
        );
    }
}

/// 24 groups of 15: per parameter set, internal and external-pure
/// signing each deterministic and hedged, internal with and without an
/// external mu, and the two HashML-DSA groups.
#[test]
fn siggen_vector_file_has_the_expected_shape() {
    let p = vectors(SIGGEN, "prompt.json");
    assert_eq!(groups(&p).len(), 24);
    let (run, excluded) = pure_groups(&p);
    assert_eq!(
        excluded, 90,
        "HashML-DSA sigGen tests excluded: {HASH_ML_DSA_REASON}"
    );
    assert_eq!(test_count(&run), 270, "pure sigGen tests run");
    for g in &run {
        assert!(
            g.get("keyFormat").is_none(),
            "the FIPS204 set has no key formats"
        );
    }
    let hedged = run.iter().filter(|g| g["deterministic"] == false).count();
    assert_eq!(hedged, 9, "3 hedged pure groups per parameter set");
}

/// The -tr1 revision: every sigGen group twice, once with the private key
/// expanded and once as the 32-byte seed. Both formats are run.
#[test]
fn siggen_tr1_vector_file_has_the_expected_shape() {
    let p = vectors(SIGGEN_TR1, "prompt.json");
    assert_eq!(groups(&p).len(), 48);
    let (run, excluded) = pure_groups(&p);
    assert_eq!(
        excluded, 180,
        "HashML-DSA sigGen-tr1 tests excluded: {HASH_ML_DSA_REASON}"
    );
    assert_eq!(test_count(&run), 540, "pure sigGen-tr1 tests run");

    let mut by_format: BTreeMap<&str, usize> = BTreeMap::new();
    for g in &run {
        let format = g["keyFormat"].as_str().unwrap();
        let key_field = match format {
            "seed" => "seed",
            "expanded" => "sk",
            other => panic!("a key format this harness does not know: {other}"),
        };
        for t in tests(g) {
            assert!(
                t.get(key_field).is_some(),
                "tcId {}: a {format} key carries `{key_field}`",
                t["tcId"]
            );
        }
        *by_format.entry(format).or_default() += tests(g).len();
    }
    assert_eq!(by_format.get("seed"), Some(&270), "seed-format tests run");
    assert_eq!(
        by_format.get("expanded"),
        Some(&270),
        "expanded-format tests run"
    );
}

/// ⛔ EVERY NEGATIVE IS COUNTED BY ITS REASON. 12 groups of 15, each
/// holding 3 of each of the four ways NIST breaks a signature and 3 valid
/// ones. If a later file drops the hint cases, this fails rather than the
/// suite quietly no longer testing hint decoding.
#[test]
fn sigver_vector_file_has_the_expected_shape() {
    let p = vectors(SIGVER, "prompt.json");
    let e = expected(SIGVER);
    let reasons = reasons(SIGVER);
    assert_eq!(groups(&p).len(), 12);
    let (run, excluded) = pure_groups(&p);
    assert_eq!(
        excluded, 45,
        "HashML-DSA sigVer tests excluded: {HASH_ML_DSA_REASON}"
    );
    assert_eq!(test_count(&run), 135, "pure sigVer tests run");

    let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
    for g in &run {
        for t in tests(g) {
            let tc = t["tcId"].as_u64().unwrap();
            let reason = reasons[&tc].as_str();
            let passes = e[&tc]["testPassed"].as_bool().unwrap();
            assert_eq!(
                passes,
                reason == VALID,
                "tcId {tc}: `{reason}` and testPassed agree"
            );
            *by_reason.entry(reason).or_default() += 1;
        }
    }
    let want: BTreeMap<&str, usize> = [
        (MODIFIED_MESSAGE, 27),
        (MODIFIED_COMMITMENT, 27),
        (MODIFIED_Z, 27),
        (MODIFIED_HINT, 27),
        (VALID, 27),
    ]
    .into();
    assert_eq!(by_reason, want, "pure sigVer cases by reason");
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
        compare("ML-DSA-87", 42, "signature", &[1, 2, 3], &[1, 2, 4]);
    })
    .unwrap_err();
    let msg = panic_message(&content);
    for needle in ["ML-DSA-87", "42", "signature", "content differs"] {
        assert!(
            msg.contains(needle),
            "a mismatch message must name {needle}: {msg}"
        );
    }

    let length = std::panic::catch_unwind(|| {
        compare("ML-DSA-65", 7, "public key", &[1, 2], &[1, 2, 3]);
    })
    .unwrap_err();
    let msg = panic_message(&length);
    assert!(
        msg.contains("LENGTH differs"),
        "a length mismatch must say so: {msg}"
    );
    assert!(
        msg.contains("ML-DSA-65") && msg.contains('7'),
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
    compare("ML-DSA-87", 1, "signature", &[9, 9, 9], &[9, 9, 9]);
}

/// The exclusion refuses a group kind it was not taught, rather than
/// quietly running or skipping it.
#[test]
fn the_exclusion_refuses_an_unknown_group_kind() {
    let unknown: Value = serde_json::json!({
        "tgId": 99, "signatureInterface": "external", "preHash": "prehash-v2"
    });
    let e = std::panic::catch_unwind(|| hash_ml_dsa_excluded(&unknown)).unwrap_err();
    let msg = panic_message(&e);
    assert!(
        msg.contains("tgId 99") && msg.contains("prehash-v2"),
        "names the group: {msg}"
    );
}

// ---------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------

/// FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal`, byte-exact for every
/// seed NIST gives, at all three parameter sets.
#[test]
fn key_gen_matches_acvp() {
    let exp = expected(KEYGEN);
    let p = vectors(KEYGEN, "prompt.json");
    let mut ran = 0;
    for g in groups(&p) {
        let set = g["parameterSet"].as_str().unwrap();
        for t in tests(g) {
            let tc = t["tcId"].as_u64().unwrap();
            let seed: [u8; 32] = hex(t["seed"].as_str().unwrap()).try_into().unwrap();
            let (pk, sk) = macula_mldsa::internal::key_gen(param(set), &seed);
            let want = &exp[&tc];
            compare(
                set,
                tc,
                "public key",
                &pk,
                &hex(want["pk"].as_str().unwrap()),
            );
            compare(
                set,
                tc,
                "private key",
                &sk,
                &hex(want["sk"].as_str().unwrap()),
            );
            ran += 1;
        }
    }
    assert_eq!(ran, 75, "keyGen cases run");
}

/// One sigVer case, as the group it came from describes it.
struct Case<'a> {
    set: &'a str,
    tc: u64,
    ps: ParameterSet,
    interface: &'a str,
    external_mu: bool,
    pk: &'a [u8],
    t: &'a Value,
}

impl Case<'_> {
    /// Verify one signature as the group's interface says to: the internal
    /// function on `M'`, the same on an externally computed `mu`, or the
    /// external function on a message and its context.
    fn verify(&self, sig: &[u8]) -> bool {
        let message = || hex(self.t["message"].as_str().unwrap());
        match (self.interface, self.external_mu) {
            ("internal", false) => {
                macula_mldsa::internal::verify(self.ps, self.pk, &message(), sig)
            }
            ("internal", true) => {
                let mu: [u8; 64] = hex(self.t["mu"].as_str().unwrap()).try_into().unwrap();
                macula_mldsa::internal::verify_mu(self.ps, self.pk, &mu, sig)
            }
            ("external", _) => macula_mldsa::verify(
                self.ps,
                self.pk,
                &message(),
                sig,
                &hex(self.t["context"].as_str().unwrap()),
            )
            .unwrap_or_else(|e| panic!("{} tcId {}: verify refused ({e:?})", self.set, self.tc)),
            (other, _) => panic!(
                "{} tcId {}: an interface this test does not know: {other:?}",
                self.set, self.tc
            ),
        }
    }
}

/// FIPS 204 Algorithms 3 and 8, `ML-DSA.Verify` and `Verify_internal`,
/// on every pure sigVer case, dispatched by NIST's interface: the internal
/// function on `M'`, the same with an externally computed `mu`, and the
/// external function on a message and its context.
///
/// ⛔ EVERY OUTCOME IS COUNTED UNDER NIST'S REASON LABEL, and the counts
/// asserted: 27 of each way NIST breaks a signature, and 27 valid. A
/// verifier that returned false for everything would pass 108 of these
/// and fail exactly the valid ones; one that skipped the hint check
/// would fail exactly the hint cases, and say so by name.
#[test]
fn sig_ver_matches_acvp_every_negative_by_its_reason() {
    let exp = expected(SIGVER);
    let reasons = reasons(SIGVER);
    let p = vectors(SIGVER, "prompt.json");
    let (run, _) = pure_groups(&p);
    let mut agreed: BTreeMap<String, usize> = BTreeMap::new();
    for g in run {
        sig_ver_group(g, &exp, &reasons, &mut agreed);
    }
    let want: BTreeMap<String, usize> = [
        MODIFIED_MESSAGE,
        MODIFIED_COMMITMENT,
        MODIFIED_Z,
        MODIFIED_HINT,
        VALID,
    ]
    .into_iter()
    .map(|r| (r.to_string(), 27))
    .collect();
    assert_eq!(agreed, want, "verify agreed with NIST, by reason");
}

/// One group of the sigVer prompt: every case verified, its outcome counted
/// under NIST's reason label.
fn sig_ver_group(
    g: &Value,
    exp: &BTreeMap<u64, Value>,
    reasons: &BTreeMap<u64, String>,
    agreed: &mut BTreeMap<String, usize>,
) {
    let set = g["parameterSet"].as_str().unwrap();
    let ps = param(set);
    let interface = g["signatureInterface"].as_str().unwrap();
    let external_mu = g.get("externalMu").and_then(Value::as_bool) == Some(true);
    for t in tests(g) {
        let tc = t["tcId"].as_u64().unwrap();
        let reason = reasons[&tc].as_str();
        let pk = hex(t["pk"].as_str().unwrap());
        let sig = hex(t["signature"].as_str().unwrap());
        let case = Case {
            set,
            tc,
            ps,
            interface,
            external_mu,
            pk: &pk,
            t,
        };
        let got = case.verify(&sig);
        let want = exp[&tc]["testPassed"].as_bool().unwrap();
        assert_eq!(
            got, want,
            "{set} tcId {tc} [{reason}], {interface} interface: verify said {got}, NIST says {want}"
        );
        *agreed.entry(reason.to_string()).or_default() += 1;
    }
}

/// ⛔ HINT REFUSALS NIST'S VECTORS NEVER REACH. Its "modified hint" cases
/// break the ordering rule, so a verifier that skipped the checks for
/// nonzero padding or a count past omega would still pass every vector.
/// Here each is broken on its own, on NIST's own valid signatures. The
/// padding fault still decodes to the ORIGINAL hint if the check is
/// skipped, so nothing downstream rejects it by accident. The count fault
/// is built so the ordering rule never objects: without the omega check,
/// decoding reads past the hint and PANICS, and verification runs on
/// untrusted input, so it must answer false instead. The untouched
/// signature is the positive control.
///
/// The third such refusal, a count running backwards, can only be planted
/// without changing the hint on a polynomial with no hints after one with
/// some, and none of NIST's 27 valid signatures has one. It is tested in
/// `internal.rs`, on signatures this crate makes, as is the norm bound,
/// which every NIST "modified z" case reaches only after the commitment
/// comparison has already refused it.
#[test]
fn malformed_hints_are_refused_even_when_they_decode_to_the_valid_hint() {
    let exp = expected(SIGVER);
    let p = vectors(SIGVER, "prompt.json");
    let (run, _) = pure_groups(&p);
    let mut broken: BTreeMap<(String, String), usize> = BTreeMap::new();
    for g in run {
        break_one_group(g, &exp, &mut broken);
    }
    for set in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        for fault in ["nonzero padding", "count past omega"] {
            let seen = broken.get(&(set.to_string(), fault.to_string()));
            assert!(
                seen.is_some_and(|&n| n > 0),
                "{set}: no valid signature could carry the fault `{fault}`, so it went untested"
            );
        }
    }
}

/// One group's valid signatures, each broken in the two ways NIST's own
/// vectors never reach, and counted by fault name.
fn break_one_group(
    g: &Value,
    exp: &BTreeMap<u64, Value>,
    broken: &mut BTreeMap<(String, String), usize>,
) {
    let set = g["parameterSet"].as_str().unwrap();
    let ps = param(set);
    let interface = g["signatureInterface"].as_str().unwrap();
    let external_mu = g.get("externalMu").and_then(Value::as_bool) == Some(true);
    for t in tests(g) {
        let tc = t["tcId"].as_u64().unwrap();
        if exp[&tc]["testPassed"] != true {
            continue;
        }
        let pk = hex(t["pk"].as_str().unwrap());
        let case = Case {
            set,
            tc,
            ps,
            interface,
            external_mu,
            pk: &pk,
            t,
        };
        let sig = hex(t["signature"].as_str().unwrap());
        assert!(case.verify(&sig), "{set} tcId {tc}: control");
        if plant_nonzero_padding(&case, &sig, ps) {
            *broken
                .entry((set.to_string(), "nonzero padding".to_string()))
                .or_default() += 1;
        }
        plant_count_past_omega(&case, &sig, ps);
        *broken
            .entry((set.to_string(), "count past omega".to_string()))
            .or_default() += 1;
    }
}

/// Nonzero padding after the last hint position: `false` when this
/// signature leaves no room for it, which the caller's counts check.
fn plant_nonzero_padding(case: &Case<'_>, sig: &[u8], ps: ParameterSet) -> bool {
    let (omega, k) = (ps.omega, ps.k);
    let y = sig.len() - (omega + k);
    let total = sig[y + omega + k - 1] as usize;
    if total >= omega {
        return false;
    }
    let mut bad = sig.to_vec();
    bad[y + total] = 1;
    assert!(
        !case.verify(&bad),
        "{} tcId {}: nonzero padding accepted",
        case.set,
        case.tc
    );
    true
}

/// Counts past omega, over positions that keep rising into the count bytes
/// themselves, so the ordering rule never objects: polynomial 0 takes
/// positions 0..omega, polynomial i claims to end at omega + i. Without the
/// omega check, decoding reads past the hint's first omega bytes and
/// indexes out of range.
fn plant_count_past_omega(case: &Case<'_>, sig: &[u8], ps: ParameterSet) {
    let (omega, k) = (ps.omega, ps.k);
    let y = sig.len() - (omega + k);
    let mut bad = sig.to_vec();
    for (j, byte) in bad[y..y + omega].iter_mut().enumerate() {
        *byte = j as u8;
    }
    for (i, byte) in bad[y + omega..y + omega + k].iter_mut().enumerate() {
        *byte = (omega + i) as u8;
    }
    assert!(
        !case.verify(&bad),
        "{} tcId {}: counts past omega accepted",
        case.set,
        case.tc
    );
}

/// Signs one sigGen or sigGen-tr1 case the way its group says: the
/// private key in its format, the interface, and `rnd` (zeros when the
/// group is deterministic).
fn sign_case(g: &Value, t: &Value) -> Vec<u8> {
    use macula_mldsa::PrivateKey;
    let ps = param(g["parameterSet"].as_str().unwrap());
    let seed: [u8; 32];
    let expanded: Vec<u8>;
    let sk = match g.get("keyFormat").and_then(Value::as_str) {
        Some("seed") => {
            seed = hex(t["seed"].as_str().unwrap()).try_into().unwrap();
            PrivateKey::Seed(&seed)
        }
        Some("expanded") | None => {
            expanded = hex(t["sk"].as_str().unwrap());
            PrivateKey::Expanded(&expanded)
        }
        Some(other) => panic!("a key format this harness does not know: {other}"),
    };
    let rnd: [u8; 32] = if g["deterministic"] == true {
        [0; 32]
    } else {
        hex(t["rnd"].as_str().unwrap()).try_into().unwrap()
    };
    let external_mu = g.get("externalMu").and_then(Value::as_bool) == Some(true);
    let signed = match (g["signatureInterface"].as_str().unwrap(), external_mu) {
        ("internal", false) => {
            macula_mldsa::internal::sign(ps, sk, &hex(t["message"].as_str().unwrap()), &rnd)
        }
        ("internal", true) => {
            let mu: [u8; 64] = hex(t["mu"].as_str().unwrap()).try_into().unwrap();
            macula_mldsa::internal::sign_mu(ps, sk, &mu, &rnd)
        }
        ("external", _) => macula_mldsa::internal::sign_message(
            ps,
            sk,
            &hex(t["message"].as_str().unwrap()),
            &hex(t["context"].as_str().unwrap()),
            &rnd,
        ),
        other => panic!("an interface this harness does not know: {other:?}"),
    };
    signed.unwrap_or_else(|e| panic!("tcId {}: signing refused ({e:?})", t["tcId"]))
}

/// Runs every pure case of a signing vector file, returning how many ran
/// per (deterministic, key format).
fn sig_gen_matches(dir: &str) -> BTreeMap<(bool, String), usize> {
    let exp = expected(dir);
    let p = vectors(dir, "prompt.json");
    let (run, _) = pure_groups(&p);
    let mut ran: BTreeMap<(bool, String), usize> = BTreeMap::new();
    for g in run {
        let set = g["parameterSet"].as_str().unwrap();
        let deterministic = g["deterministic"] == true;
        let format = g
            .get("keyFormat")
            .and_then(Value::as_str)
            .unwrap_or("expanded");
        let interface = g["signatureInterface"].as_str().unwrap();
        for t in tests(g) {
            let tc = t["tcId"].as_u64().unwrap();
            let op = format!(
                "signature ({interface}, {}, {format} key)",
                if deterministic {
                    "deterministic"
                } else {
                    "hedged"
                }
            );
            compare(
                set,
                tc,
                &op,
                &sign_case(g, t),
                &hex(exp[&tc]["signature"].as_str().unwrap()),
            );
            *ran.entry((deterministic, format.to_string())).or_default() += 1;
        }
    }
    ran
}

/// FIPS 204 Algorithms 2 and 7, byte-exact on every pure sigGen case:
/// deterministic and hedged, every interface, all three parameter sets.
#[test]
fn sig_gen_matches_acvp() {
    let ran = sig_gen_matches(SIGGEN);
    let want: BTreeMap<(bool, String), usize> = [
        ((true, "expanded".to_string()), 135),
        ((false, "expanded".to_string()), 135),
    ]
    .into();
    assert_eq!(ran, want, "sigGen cases run, by variant and key format");
}

/// The -tr1 revision: the same signing with the private key given BOTH
/// ways, expanded and as its 32-byte seed.
#[test]
fn sig_gen_tr1_matches_acvp_with_both_key_formats() {
    let ran = sig_gen_matches(SIGGEN_TR1);
    let want: BTreeMap<(bool, String), usize> = [
        ((true, "expanded".to_string()), 135),
        ((false, "expanded".to_string()), 135),
        ((true, "seed".to_string()), 135),
        ((false, "seed".to_string()), 135),
    ]
    .into();
    assert_eq!(ran, want, "sigGen-tr1 cases run, by variant and key format");
}
