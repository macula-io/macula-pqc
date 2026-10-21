//! No secret survives on the heap.
//!
//! Every heap block freed while ML-KEM runs is scanned, before it goes
//! back to the system, for the secrets of that run: seeds, PRF outputs,
//! noise polynomials, the secret key, shared secrets. A block that still
//! holds one was freed without being wiped.
//!
//! ⚠ THIS FILE CONTAINS `unsafe`, as does macula-mldsa's heap_residue.rs,
//! and they are the only two files in the workspace that do. Scanning
//! freed memory takes a global allocator, and one cannot be written
//! without it. The crates themselves forbid unsafe code;
//! this is a test binary instrumenting them. Its allocator hands out zeroed
//! memory, so every byte it later scans has been initialised.
//!
//! ⚠ IT MEASURES THE HEAP ONLY. Stack values are wiped by construction,
//! and safe code cannot observe whether that held. Copies the compiler
//! makes when it moves or spills a value are beyond any of this.
//!
//! One test in this file, deliberately: the allocator is process-wide, and
//! a second test running beside it would free its own secrets into the
//! scan.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use macula_keccak::{sha3_256, sha3_512, shake256};
use macula_mlkem::poly::{ntt, Poly};
use macula_mlkem::sample::{prf, sample_poly_cbd};
use macula_mlkem::{decaps, internal, ParameterSet, ML_KEM_1024, ML_KEM_512, ML_KEM_768};

static SCANNING: AtomicBool = AtomicBool::new(false);
static NEEDLES: OnceLock<Vec<(String, Vec<u8>)>> = OnceLock::new();
const MAX_NEEDLES: usize = 1024;
static HITS: [AtomicBool; MAX_NEEDLES] = [const { AtomicBool::new(false) }; MAX_NEEDLES];

/// Look for each planted needle in a block that is being freed.
///
/// # Safety
///
/// `ptr` must be a live allocation of at least `size` zeroed bytes.
unsafe fn scan_for_needles(ptr: *const u8, size: usize) {
    let Some(needles) = NEEDLES.get() else {
        return;
    };
    // SAFETY: the caller promises a live allocation of `size` bytes,
    // and it was zeroed when it was handed out.
    let block = unsafe { std::slice::from_raw_parts(ptr, size) };
    for (i, (_, needle)) in needles.iter().enumerate() {
        if block.windows(needle.len()).any(|w| w == needle.as_slice()) {
            HITS[i].store(true, Ordering::SeqCst);
        }
    }
}

struct Scanning;

unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if SCANNING.load(Ordering::SeqCst) {
            // SAFETY: the block is still allocated, `layout.size()` bytes
            // long, and was zeroed when it was handed out.
            unsafe { scan_for_needles(ptr, layout.size()) };
        }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

const SETS: [ParameterSet; 3] = [ML_KEM_512, ML_KEM_768, ML_KEM_1024];

/// Random-looking bytes from a label, so no seed is a pattern like
/// `[1; 32]` that some unrelated buffer could hold by chance.
fn seed(label: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(label.as_bytes(), &mut out);
    out
}

fn poly_bytes(f: &Poly) -> Vec<u8> {
    f.iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// `(G(input) first half, second half)`.
fn g(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let out = sha3_512(input);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

/// One parameter set's inputs, and every secret its run must not leave on
/// the heap, worked out independently of the code under test where the
/// specification makes that possible.
struct Run {
    p: ParameterSet,
    d: [u8; 32],
    z: [u8; 32],
    m: [u8; 32],
    ek: Vec<u8>,
    dk: Vec<u8>,
    c: Vec<u8>,
    c_modified: Vec<u8>,
}

impl Run {
    fn new(p: ParameterSet, needles: &mut Vec<(String, Vec<u8>)>) -> Run {
        let name = p.name;
        let d = seed(&format!("{name} d"));
        let z = seed(&format!("{name} z"));
        let m = seed(&format!("{name} m"));
        let (ek, dk) = internal::key_gen(p, &d, &z);
        let (c, shared) = internal::encaps(p, &ek, &m).unwrap();
        let mut c_modified = c.clone();
        c_modified[0] ^= 1;

        let mut add =
            |what: String, bytes: &[u8]| needles.push((format!("{name} {what}"), bytes.to_vec()));
        add("d".into(), &d);
        add("z".into(), &z);
        add("m".into(), &m);
        add_key_gen_secrets(&mut add, p, &d, &dk);
        add_encapsulation_secrets(&mut add, p, &m, &ek, &shared[..]);
        add_rejection_secrets(&mut add, &z, &c, &c_modified);

        Run {
            p,
            d,
            z,
            m,
            ek,
            dk: dk.to_vec(),
            c,
            c_modified,
        }
    }

    /// Every operation, with every output dropped before this returns.
    fn exercise(&self) {
        drop(internal::key_gen(self.p, &self.d, &self.z));
        drop(internal::encaps(self.p, &self.ek, &self.m));
        drop(decaps(self.p, &self.dk, &self.c));
        drop(decaps(self.p, &self.dk, &self.c_modified));
    }
}

/// Key generation: (rho, sigma) = G(d || k); s from PRF counters
/// 0..k, e from k..2k, both taken to the NTT domain.
fn add_key_gen_secrets(
    add: &mut impl FnMut(String, &[u8]),
    p: ParameterSet,
    d: &[u8; 32],
    dk: &[u8],
) {
    let k = p.k;
    let mut dk_seed = d.to_vec();
    dk_seed.push(k as u8);
    let (_, sigma) = g(&dk_seed);
    add("sigma".into(), &sigma);
    for i in 0..2 * k {
        let bytes = prf(p.eta1, &sigma, i as u8).to_vec();
        add(format!("prf(sigma, {i})"), &bytes);
        let mut f = sample_poly_cbd(p.eta1, &bytes);
        ntt(&mut f);
        let which = key_gen_secret(i, k);
        add(format!("{which}[{}]", i % k), &poly_bytes(&f));
    }
    for (i, window) in dk[..384 * k].as_chunks::<32>().0.iter().enumerate() {
        add(format!("dk_pke bytes {}..{}", 32 * i, 32 * i + 32), window);
    }
}

/// The name of the key-generation polynomial PRF counter `i` produces.
fn key_gen_secret(i: usize, k: usize) -> &'static str {
    if i < k {
        "s_hat"
    } else {
        "e_hat"
    }
}

/// Encapsulation: (K, r) = G(m || H(ek)); y from PRF counters
/// 0..k (NTT domain), e1 from k..2k, e2 from 2k.
fn add_encapsulation_secrets(
    add: &mut impl FnMut(String, &[u8]),
    p: ParameterSet,
    m: &[u8; 32],
    ek: &[u8],
    shared: &[u8],
) {
    let k = p.k;
    let mut encaps_seed = m.to_vec();
    encaps_seed.extend_from_slice(&sha3_256(ek));
    let (big_k, r) = g(&encaps_seed);
    assert_eq!(
        big_k.as_slice(),
        shared,
        "{}: K worked out independently",
        p.name
    );
    add("K".into(), &big_k);
    add("r".into(), &r);
    for i in 0..=2 * k {
        let eta = encaps_eta(p, i, k);
        let bytes = prf(eta, &r, i as u8).to_vec();
        add(format!("prf(r, {i})"), &bytes);
        let mut f = sample_poly_cbd(eta, &bytes);
        let which = encaps_secret(&mut f, i, k);
        add(which, &poly_bytes(&f));
    }
}

/// The CBD width of encapsulation polynomial `i`: `eta1` for the `y`
/// counters, `eta2` for `e1` and `e2`.
fn encaps_eta(p: ParameterSet, i: usize, k: usize) -> usize {
    if i < k {
        p.eta1
    } else {
        p.eta2
    }
}

/// The name of encapsulation polynomial `i`, moving the `y` counters to
/// the NTT domain on the way.
fn encaps_secret(f: &mut Poly, i: usize, k: usize) -> String {
    if i < k {
        ntt(f);
        return format!("y_hat[{i}]");
    }
    if i < 2 * k {
        return format!("e1[{}]", i - k);
    }
    "e2".to_string()
}

/// Decapsulation: the implicit-rejection secret J(z || c), for the valid
/// ciphertext and for the modified one.
fn add_rejection_secrets(
    add: &mut impl FnMut(String, &[u8]),
    z: &[u8; 32],
    c: &[u8],
    c_modified: &[u8],
) {
    for (what, cipher) in [("K_bar(valid c)", c), ("K_bar(modified c)", c_modified)] {
        let mut input = z.to_vec();
        input.extend_from_slice(cipher);
        let mut k_bar = [0u8; 32];
        shake256(&input, &mut k_bar);
        add(what.into(), &k_bar);
    }
}

#[test]
fn no_secret_survives_on_the_heap() {
    let mut needles = Vec::new();
    let runs: Vec<Run> = SETS.iter().map(|&p| Run::new(p, &mut needles)).collect();
    assert!(needles.len() <= MAX_NEEDLES, "{} needles", needles.len());
    let needles = NEEDLES.get_or_init(|| needles);

    SCANNING.store(true, Ordering::SeqCst);
    runs.iter().for_each(Run::exercise);
    SCANNING.store(false, Ordering::SeqCst);

    let survived: Vec<&str> = needles
        .iter()
        .enumerate()
        .filter(|(i, _)| HITS[*i].load(Ordering::SeqCst))
        .map(|(_, (name, _))| name.as_str())
        .collect();
    assert!(
        survived.is_empty(),
        "{} of {} secrets were found in heap blocks freed without being wiped:\n  {}",
        survived.len(),
        needles.len(),
        survived.join("\n  ")
    );
}
