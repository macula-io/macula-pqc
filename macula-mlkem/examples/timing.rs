//! Timing measurement for ML-KEM, dudect-style.
//!
//! **ML-KEM-768 and ML-KEM-1024**, each with its own controls. 768 is the
//! set negotiated on the wire (`secp256r1MLKEM768`), so it is the one that
//! matters most once this crate replaces `aws-lc-rs`'s. 512 is not timed:
//! nothing negotiates it.
//!
//! Run with `scripts/timing.sh` (release build; timing in a debug build
//! measures a different binary from the one that ships).
//!
//! # Method
//!
//! Each test times two input classes in pairs: one input of each class,
//! timed back to back in random order. A t-test on the paired
//! differences asks whether one class is slower. As in dudect, the test
//! is repeated on pairs cropped at several percentiles, to discard
//! long-tail noise from interrupts and scheduling, and the largest |t| is
//! reported. |t| above 4.5 is a leak detected with high confidence.
//!
//! Pairing is what makes a leak of a few tens of nanoseconds visible
//! inside a decapsulation. The clock rate drifts over a run by far more
//! than that, and drift is shared by both halves of a pair, so it cancels
//! in the difference. Measured on the same samples, dudect's independent
//! two-sample test missed the positive control that the paired test
//! flagged.
//!
//! ⚠ A result below the threshold means NO LEAK WAS DETECTED at that
//! number of measurements, on this machine, with this compiler. It does
//! not prove the code constant-time.
//!
//! # Positive control
//!
//! Decapsulation followed by an early-exit `==` of the ciphertext against
//! the fixed valid one: a compare of the whole ciphertext for one class,
//! an exit at byte 0 for the other. That is the leak a non-constant-time
//! re-encryption check has, inside the noise of a whole decapsulation.
//! A bare `==` timed on its own is flagged at any n and proves only that
//! the statistics run; this one proves the instrument can see the leak
//! the constant-time compare exists to prevent. If it is not flagged, the
//! other results mean nothing and the run exits non-zero.
//!
//! # Why the key is fixed in every test
//!
//! Expanding the matrix A rejection-samples, so its duration depends on
//! `rho`. That is not a leak, because `rho` is public: it is part of the
//! encapsulation key. Varying the key between classes would vary `rho` and
//! produce a timing difference that means nothing. With one fixed key, A
//! is the same in both classes. Key generation is not tested for the same
//! reason: its secret seed also determines `rho`, so it cannot be varied
//! without varying public data.

use std::hint::black_box;
use std::time::Instant;

use macula_mlkem::internal::{encaps, key_gen};
use macula_mlkem::{decaps, ParameterSet, Zeroizing, ML_KEM_1024, ML_KEM_768};

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
    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
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
        if d.len() > 1000 {
            best = best.max(paired_t(&d).abs());
        }
    }
    best
}

/// Times `op` on `n` inputs as `n / 2` pairs, one input of each class
/// per pair, timed back to back in random order.
///
/// ⚠ INPUTS ARE PREPARED BEFORE THE CLOCK STARTS. Generating an input
/// inside the timed region makes the two classes differ by the cost of
/// generating them, which is exactly the signal the test looks for: a
/// random ciphertext costs RNG work, a random valid one costs a whole
/// encapsulation. Only `op` is ever timed. Batches keep memory bounded.
///
/// ⚠ EVERY INPUT IS COPIED INTO ONE STAGING BUFFER BEFORE ITS CLOCK
/// STARTS. Where an input sits in memory changes how long reading it
/// takes: its allocation path, its alignment, whether it is cached,
/// whether the prefetcher ran into it from its neighbour. Any of those
/// that differs by class is flagged as a leak in byte-identical data, and
/// the negative control caught two of them. Staged, both classes are read
/// from the same address, warm.
/// Warm caches and branch predictors before recording anything.
#[inline(always)]
fn warm<I>(op: &mut impl FnMut(&I), batch: &[(bool, I, I)]) {
    batch.iter().take(500).for_each(|(_, x, y)| {
        op(x);
        op(y);
    });
}

/// `(a, b)` when class A ran first, `(b, a)` otherwise. The random choice
/// fixes which class is timed first; the recorded pair is put back into
/// class order so the t-test compares A with B, not first with second.
#[inline(always)]
fn class_order<T>(a_first: bool, a: T, b: T) -> (T, T) {
    if a_first {
        (a, b)
    } else {
        (b, a)
    }
}

/// One pair timed back to back in the drawn class order, returned in class
/// order.
///
/// ⚠ BOTH HALVES ARE STAGED THROUGH ONE BUFFER BEFORE THEIR CLOCK STARTS,
/// as `measure` describes: same address, warm, for both classes.
#[inline(always)]
fn time_pair<I: Copy>(op: &mut impl FnMut(&I), case: &(bool, I, I)) -> (f64, f64) {
    let (a_first, x, y) = *case;
    let (first, second) = class_order(a_first, &x, &y);
    let mut stage = *first;
    black_box(&mut stage);
    let start = Instant::now();
    op(&stage);
    let d1 = start.elapsed().as_nanos() as f64;
    stage = *second;
    black_box(&mut stage);
    let start = Instant::now();
    op(&stage);
    let d2 = start.elapsed().as_nanos() as f64;
    class_order(a_first, d1, d2)
}

fn measure<I: Copy>(
    n: usize,
    rng: &mut Prng,
    mut prepare: impl FnMut(bool, &mut Prng) -> I,
    mut op: impl FnMut(&I),
) -> Vec<(f64, f64)> {
    const BATCH: usize = 5_000;
    let total = n / 2;
    let mut pairs = Vec::with_capacity(total);
    let mut warmed = false;
    while pairs.len() < total {
        let size = BATCH.min(total - pairs.len());
        let batch: Vec<(bool, I, I)> = (0..size)
            .map(|_| {
                let a_first = rng.next() & 1 == 0;
                (a_first, prepare(true, rng), prepare(false, rng))
            })
            .collect();
        if !warmed {
            warm(&mut op, &batch);
            warmed = true;
        }
        for case in batch.iter() {
            pairs.push(time_pair(&mut op, case));
        }
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
        "{name:<46} n={:>7}  median A {:>7.0} ns  B {:>7.0} ns  max|t| {:>7.2}  {verdict}",
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

/// One parameter set's fixed key material, message and valid ciphertext.
///
/// The key is fixed in every test because expanding the matrix A
/// rejection-samples, so its duration depends on `rho`. That is not a
/// leak, because `rho` is public: it is part of the encapsulation key.
/// Varying the key between classes would vary `rho` and produce a timing
/// difference that means nothing. Key generation is not tested for the
/// same reason: its secret seed also determines `rho`, so it cannot be
/// varied without varying public data.
struct Fixed<const CT: usize> {
    p: ParameterSet,
    ek: Vec<u8>,
    dk: Zeroizing<Vec<u8>>,
    m: [u8; 32],
    c: [u8; CT],
}

impl<const CT: usize> Fixed<CT> {
    /// Draw the one fixed key, message and matching ciphertext the set's
    /// tests share.
    fn draw(p: ParameterSet, rng: &mut Prng) -> Self {
        // --- one fixed key throughout ---
        let d: [u8; 32] = rng.bytes();
        let z: [u8; 32] = rng.bytes();
        let (ek, dk) = key_gen(p, &d, &z);
        let m: [u8; 32] = rng.bytes();
        let c: [u8; CT] = encaps(p, &ek, &m).unwrap().0.try_into().unwrap();
        Self { p, ek, dk, m, c }
    }

    /// A random ciphertext: the right length, a decapsulation of nothing.
    fn random_ciphertext(&self, rng: &mut Prng) -> [u8; CT] {
        let mut bad = [0u8; CT];
        rng.fill(&mut bad);
        bad
    }

    /// A valid ciphertext of `m`, by re-running the deterministic
    /// encapsulation the random-valid test also uses.
    fn valid_ciphertext_of(&self, m: &[u8; 32]) -> [u8; CT] {
        encaps(self.p, &self.ek, m).unwrap().0.try_into().unwrap()
    }
}

/// The positive control and the first real test, in that order: a planted
/// compare leak inside decapsulation, then valid vs invalid ciphertext.
fn decaps_control_and_validity<const CT: usize>(
    fx: &Fixed<CT>,
    n: usize,
    rng: &mut Prng,
) -> (f64, f64) {
    let p = fx.p;
    let dk = &fx.dk;
    let fixed_c = fx.c;
    let pairs = measure(
        n,
        rng,
        |class, rng| {
            if class {
                fixed_c
            } else {
                fx.random_ciphertext(rng)
            }
        },
        |c| {
            black_box(decaps(p, black_box(dk), black_box(&c[..])).unwrap());
            black_box(black_box(&c[..]) == black_box(&fixed_c[..]));
        },
    );
    let control = report("CONTROL decaps + early-exit == (must be)", &pairs);

    let pairs = measure(
        n,
        rng,
        |class, rng| {
            if class {
                fixed_c
            } else {
                fx.random_ciphertext(rng)
            }
        },
        |c| {
            black_box(decaps(p, black_box(dk), black_box(&c[..])).unwrap());
        },
    );
    let t1 = report("decaps: valid vs invalid ciphertext", &pairs);
    (control, t1)
}

/// The negative control, then decapsulation of a fixed vs a random valid
/// ciphertext.
///
/// --- negative control: identical data, two preparation paths ---
///
/// Both classes decapsulate the SAME ciphertext bytes. Class B gets them
/// by re-running the deterministic encapsulation of the same message, the
/// path the random-valid test uses. If this is flagged, the difference
/// comes from how inputs are prepared, not from what they contain, and
/// the fixed-vs-random result cannot be read as a leak.
fn decaps_negative_and_random<const CT: usize>(
    fx: &Fixed<CT>,
    n: usize,
    rng: &mut Prng,
) -> (f64, f64) {
    let p = fx.p;
    let dk = &fx.dk;
    let fixed_c = fx.c;
    let pairs = measure(
        n,
        rng,
        |class, _| {
            if class {
                fixed_c
            } else {
                fx.valid_ciphertext_of(&fx.m)
            }
        },
        |c| {
            black_box(decaps(p, black_box(dk), black_box(&c[..])).unwrap());
        },
    );
    let negative = report("NEG CONTROL identical data (must NOT be)", &pairs);

    let pairs = measure(
        n,
        rng,
        |class, rng| {
            if class {
                fixed_c
            } else {
                fx.valid_ciphertext_of(&rng.bytes())
            }
        },
        |c| {
            black_box(decaps(p, black_box(dk), black_box(&c[..])).unwrap());
        },
    );
    let t2 = report("decaps: fixed vs random valid ciphertext", &pairs);
    (negative, t2)
}

/// Encapsulation against a fixed vs a random message.
fn encaps_fixed_vs_random<const CT: usize>(fx: &Fixed<CT>, n: usize, rng: &mut Prng) -> f64 {
    let p = fx.p;
    let ek = &fx.ek;
    let fixed_m = fx.m;
    let pairs = measure(
        n,
        rng,
        |class, rng| if class { fixed_m } else { rng.bytes() },
        |m| {
            black_box(encaps(p, black_box(ek), black_box(m)).unwrap());
        },
    );
    report("encaps: fixed vs random message", &pairs)
}

/// What a run's values say, control first: without a detected control leak
/// the other results mean nothing, and identical data flagged means the
/// preparation path is showing through.
fn verdict(control: f64, negative: f64, tests: [f64; 3], n: usize) -> Outcome {
    if control <= THRESHOLD {
        println!("  INSTRUMENT BROKEN: the control leak was not detected, so the other results mean nothing.");
        return Outcome::InstrumentBroken;
    }
    if negative > THRESHOLD {
        println!("  INSTRUMENT BIASED: identical data was flagged, so a flag elsewhere may be the preparation path, not a leak.");
        return Outcome::InstrumentBiased;
    }
    if tests.iter().any(|&t| t > THRESHOLD) {
        println!("  LEAK DETECTED in at least one test.");
        return Outcome::LeakDetected;
    }
    println!("  Control detected; no leak detected in any test at n = {n}.");
    Outcome::NoLeakDetected
}

/// Every test for one parameter set. `CT` is its ciphertext length: the
/// inputs are fixed-size arrays so they can be staged; see `measure`.
fn time_set<const CT: usize>(p: ParameterSet, n: usize, rng: &mut Prng) -> Outcome {
    println!("{}", p.name);

    let fx = Fixed::<CT>::draw(p, rng);
    let (control, t1) = decaps_control_and_validity(&fx, n, rng);
    let (negative, t2) = decaps_negative_and_random(&fx, n, rng);
    let t3 = encaps_fixed_vs_random(&fx, n, rng);
    let outcome = verdict(control, negative, [t1, t2, t3], n);
    println!();
    outcome
}

fn main() {
    let n: usize = std::env::var("TIMING_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let mut rng = Prng(0x9e37_79b9_7f4a_7c15);
    println!("ML-KEM timing, {n} measurements per test, threshold |t| > {THRESHOLD}\n");

    let worst = [
        time_set::<1088>(ML_KEM_768, n, &mut rng),
        time_set::<1568>(ML_KEM_1024, n, &mut rng),
    ]
    .into_iter()
    .min()
    .unwrap();
    std::process::exit(worst.exit_code());
}
