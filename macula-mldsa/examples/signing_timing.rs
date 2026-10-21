//! Timing measurement for ML-DSA signing, dudect-style, against what FIPS
//! 204 permits signing's time to depend on.
//!
//! Run with `scripts/timing.sh` (release build; timing in a debug build
//! measures a different binary from the one that ships).
//!
//! ML-DSA-87, the set macula's identities use, and ML-DSA-65, the one set
//! with `eta = 4` and so its own packing and sampling. ML-DSA-44 shares
//! ML-DSA-87's `eta` and every code path, and is not timed.
//!
//! # What signing's time may depend on
//!
//! FIPS 204 signing loops until an attempt passes its checks, so its time
//! varies with the NUMBER OF ATTEMPTS, and the standard permits that: the
//! count depends on the secret only through whether a candidate would
//! leak it. Within one attempt, ExpandA rejection-samples from the public
//! `rho` and SampleInBall from the commitment hash `c~`, which the
//! signature publishes. Those are allowed to vary too. Nothing else is.
//!
//! So both classes here share every one of those inputs: the same `rho`,
//! `K`, `tr`, `mu` and `rnd`, which fix `A`, the mask `y`, `w`, `c~` and the
//! challenge, and every input is chosen to sign in exactly ONE attempt.
//! The classes differ only in the secret polynomials `s1`, `s2` and `t0`:
//! class A one fixed set, class B fresh realistic ones from key
//! generation. What is left to differ in time is the arithmetic on the
//! secret, which is exactly what must not.
//!
//! # Method
//!
//! As in macula-mlkem's harness: inputs are timed in pairs, one of each
//! class back to back in random order, and a t-test on the paired
//! differences asks whether one class is slower. It is repeated on pairs
//! cropped at several percentiles and the largest |t| is reported; above
//! 4.5 is a leak detected with high confidence. Pairing cancels the clock
//! drift a whole signature's duration would otherwise drown a leak in.
//! Every input is copied into one staging buffer before its clock starts,
//! so both classes are read from the same address.
//!
//! ⚠ A result below the threshold means NO LEAK WAS DETECTED at that
//! number of measurements, on this machine, with this compiler. It does
//! not prove the code constant-time.
//!
//! # Controls
//!
//! POSITIVE: signing followed by a branch on each byte of the packed
//! secret polynomials, taken for about 3% of them, about as often as a
//! hint bit is set. With class A's fixed bytes the branch predictor partly
//! learns the pattern; with class B's fresh ones it mispredicts. That is
//! the shape, and roughly the size, of the one difference this harness
//! found in its first runs: HintBitPack branched on each hint bit (see
//! below). An early-exit `==` on the key was tried first and was not
//! flagged at 4,000 measurements while the real hint branch was, so it
//! calibrated nothing. If this control is not flagged, the other results
//! mean nothing and the run exits 2.
//!
//! NEGATIVE: both classes sign with the SAME key bytes, class B's produced
//! by re-running key generation from class A's seed. If identical data is
//! flagged, a flag elsewhere may be how inputs were prepared, not what they
//! contain, and the run exits 3.
//!
//! # What the first runs found
//!
//! HintBitPack skipped its write for each zero hint bit. The hint depends
//! on the secret key, so fixed-versus-random secrets differed by about
//! 200 ns. At 40,000 measurements the branching version is flagged at
//! |t| 9.73 (ML-DSA-87) and 15.15 (ML-DSA-65); the branch-free one that
//! replaced it measures 1.48 and 0.90. The hint is published in the
//! signature, so this revealed nothing the signature does not, but it
//! would hide a real leak of the same size behind a permitted one.

use std::hint::black_box;
use std::time::Instant;

use macula_mldsa::internal::{key_gen, sign_mu_counting_attempts};
use macula_mldsa::{ParameterSet, PrivateKey, ML_DSA_65, ML_DSA_87};

const THRESHOLD: f64 = 4.5;

/// xorshift64*: deterministic, reproducible input generation for the
/// harness. Not used for anything cryptographic.
struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
        out
    }
}

/// One-sample t of paired differences against zero.
fn paired_t(d: &[f64]) -> f64 {
    let m = d.iter().sum::<f64>() / d.len() as f64;
    let v = d.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (d.len() - 1) as f64;
    m / (v / d.len() as f64).sqrt()
}

/// Largest |paired t| over all pairs, and over the pairs whose slower
/// measurement falls below each of several percentiles.
fn max_abs_paired_t(pairs: &[(f64, f64)]) -> f64 {
    let mut slower: Vec<f64> = pairs.iter().map(|(a, b)| a.max(*b)).collect();
    slower.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let diffs = |cut: f64| -> Vec<f64> {
        pairs
            .iter()
            .filter(|(a, b)| a.max(*b) <= cut)
            .map(|(a, b)| a - b)
            .collect()
    };
    let mut best = paired_t(&diffs(f64::INFINITY)).abs();
    for pct in [0.05, 0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99] {
        let d = diffs(slower[((slower.len() as f64) * pct) as usize]);
        if d.len() > 200 {
            best = best.max(paired_t(&d).abs());
        }
    }
    best
}

/// Times `op` on `n` inputs as `n / 2` pairs, one input of each class per
/// pair, timed back to back in random order. Class B's inputs are drawn
/// in turn from `b_pool`. Every input is staged into one buffer before
/// its clock starts; only `op` is timed.
fn measure<I: Copy>(
    n: usize,
    rng: &mut Prng,
    a: I,
    b_pool: &[I],
    mut op: impl FnMut(&I),
) -> Vec<(f64, f64)> {
    let total = n / 2;
    let mut pairs = Vec::with_capacity(total);
    for b in b_pool.iter().take(20) {
        op(&a);
        op(b);
    }
    let mut stage: I;
    for i in 0..total {
        let b = b_pool[i % b_pool.len()];
        let a_first = rng.next() & 1 == 0;
        let (first, second) = if a_first { (a, b) } else { (b, a) };
        stage = first;
        black_box(&mut stage);
        let start = Instant::now();
        op(&stage);
        let d1 = start.elapsed().as_nanos() as f64;
        stage = second;
        black_box(&mut stage);
        let start = Instant::now();
        op(&stage);
        let d2 = start.elapsed().as_nanos() as f64;
        pairs.push(if a_first { (d1, d2) } else { (d2, d1) });
    }
    pairs
}

fn report(name: &str, pairs: &[(f64, f64)]) -> f64 {
    let a: Vec<f64> = pairs.iter().map(|p| p.0).collect();
    let b: Vec<f64> = pairs.iter().map(|p| p.1).collect();
    let t = max_abs_paired_t(pairs);
    let med = |x: &[f64]| {
        let mut v = x.to_vec();
        v.sort_by(|p, q| p.partial_cmp(q).unwrap());
        v[v.len() / 2]
    };
    let verdict = if t > THRESHOLD {
        "LEAK DETECTED"
    } else {
        "no leak detected"
    };
    println!(
        "{name:<50} n={:>6}  median A {:>8.0} ns  B {:>8.0} ns  max|t| {:>6.2}  {verdict}",
        2 * pairs.len(),
        med(&a),
        med(&b),
        t
    );
    t
}

/// What one parameter set's run found, worst first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome {
    /// The control leak was not detected: nothing else can be read.
    InstrumentBroken,
    /// Identical data was flagged: a flag elsewhere may be the
    /// preparation path, not a leak.
    InstrumentBiased,
    LeakDetected,
    NoLeakDetected,
}

impl Outcome {
    fn exit_code(self) -> i32 {
        match self {
            Outcome::InstrumentBroken => 2,
            Outcome::InstrumentBiased => 3,
            Outcome::LeakDetected => 1,
            Outcome::NoLeakDetected => 0,
        }
    }
}

/// How many attempts `sk` takes to sign `mu` with `rnd`.
fn attempts(p: ParameterSet, sk: &[u8], mu: &[u8; 64], rnd: &[u8; 32]) -> u32 {
    sign_mu_counting_attempts(p, PrivateKey::Expanded(sk), mu, rnd)
        .unwrap()
        .1
}

/// The positive control: sign, then branch on the secret bytes.
fn sign_and_branch<const SK: usize>(p: ParameterSet, mu: &[u8; 64], rnd: &[u8; 32], sk: &[u8; SK]) {
    black_box(
        sign_mu_counting_attempts(p, PrivateKey::Expanded(black_box(&sk[..])), mu, rnd).unwrap(),
    );
    let secret_bytes = 32 * (p.l + p.k) * if p.eta == 2 { 3 } else { 4 };
    let mut taken = 0u32;
    for &b in black_box(&sk[128..128 + secret_bytes]) {
        if b < 8 {
            taken = black_box(taken + 1);
        }
    }
    black_box(taken);
}

/// Every test for one parameter set. `SK` is its private key length: the
/// inputs are fixed-size arrays so they can be staged.
fn time_set<const SK: usize>(p: ParameterSet, n: usize, rng: &mut Prng) -> Outcome {
    println!("{}", p.name);
    let rnd: [u8; 32] = rng.bytes();

    // Class A: a key and a message representative that sign in one attempt.
    let (seed_a, sk_a, mu) = loop {
        let seed: [u8; 32] = rng.bytes();
        let sk: [u8; SK] = (*key_gen(p, &seed).1).clone().try_into().unwrap();
        let mu: [u8; 64] = rng.bytes();
        if attempts(p, &sk, &mu, &rnd) == 1 {
            break (seed, sk, mu);
        }
    };

    // Class B: fresh secret polynomials from key generation, under class
    // A's rho, K and tr, kept only when they too sign in one attempt.
    let pool_size = 200;
    let mut pool: Vec<[u8; SK]> = Vec::with_capacity(pool_size);
    let mut tried = 0;
    while pool.len() < pool_size {
        tried += 1;
        let seed: [u8; 32] = rng.bytes();
        let mut sk: [u8; SK] = (*key_gen(p, &seed).1).clone().try_into().unwrap();
        sk[..128].copy_from_slice(&sk_a[..128]);
        if attempts(p, &sk, &mu, &rnd) == 1 {
            pool.push(sk);
        }
    }
    println!("  class B: {pool_size} secret sets signing in one attempt, of {tried} tried");

    let sign_one = |sk: &[u8; SK]| {
        black_box(
            sign_mu_counting_attempts(p, PrivateKey::Expanded(black_box(&sk[..])), &mu, &rnd)
                .unwrap(),
        );
    };

    let pairs = measure(n, rng, sk_a, &pool, |sk| sign_and_branch(p, &mu, &rnd, sk));
    let control = report("CONTROL sign + branch on secret bytes (must be)", &pairs);

    let same: [u8; SK] = (*key_gen(p, &seed_a).1).clone().try_into().unwrap();
    let pairs = measure(n, rng, sk_a, &[same], sign_one);
    let negative = report("NEG CONTROL identical key bytes (must NOT be)", &pairs);

    let pairs = measure(n, rng, sk_a, &pool, sign_one);
    let t = report("sign: fixed vs random s1, s2, t0, one attempt", &pairs);

    let outcome = if control <= THRESHOLD {
        println!("  INSTRUMENT BROKEN: the control leak was not detected, so the other results mean nothing.");
        Outcome::InstrumentBroken
    } else if negative > THRESHOLD {
        println!("  INSTRUMENT BIASED: identical data was flagged, so a flag elsewhere may be the preparation path, not a leak.");
        Outcome::InstrumentBiased
    } else if t > THRESHOLD {
        println!("  LEAK DETECTED.");
        Outcome::LeakDetected
    } else {
        println!("  Control detected; no leak detected at n = {n}.");
        Outcome::NoLeakDetected
    };
    println!();
    outcome
}

fn main() {
    let n: usize = std::env::var("TIMING_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40_000);
    let mut rng = Prng(0x9e37_79b9_7f4a_7c15);
    println!("ML-DSA signing timing, {n} measurements per test, threshold |t| > {THRESHOLD}\n");

    let worst = [
        time_set::<4896>(ML_DSA_87, n, &mut rng),
        time_set::<4032>(ML_DSA_65, n, &mut rng),
    ]
    .into_iter()
    .min()
    .unwrap();
    std::process::exit(worst.exit_code());
}
