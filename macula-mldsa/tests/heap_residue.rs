//! No secret survives on the heap.
//!
//! Every heap block freed while ML-DSA runs is scanned, before it goes
//! back to the system, for the secrets of that run: the seed `xi`, the
//! private seeds `rho'` and `K`, the private key's secret bytes, the
//! signing randomness `rnd` and the per-signature seed `rho''`. A block
//! that still holds one was freed without being wiped.
//!
//! ⚠ THIS FILE CONTAINS `unsafe`, as does macula-mlkem's heap_residue.rs,
//! and they are the only two files in the workspace that do. Scanning
//! freed memory takes a global allocator, and one cannot be written
//! without it. The crates themselves forbid unsafe code; this is a test
//! binary instrumenting them. Its allocator hands out zeroed memory, so
//! every byte it later scans has been initialised.
//!
//! ⚠ IT MEASURES THE HEAP ONLY, and in this crate the heap holds little:
//! the private key a caller receives, and the key a seed expands into for
//! each signature. `s1`, `s2`, `t0`, the mask `y` and every other working
//! secret live in stack arrays wiped by construction, which safe code
//! cannot observe. Copies the compiler makes when it moves or spills a
//! value are beyond any of this.
//!
//! One test in this file, deliberately: the allocator is process-wide, and
//! a second test running beside it would free its own secrets into the
//! scan.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use macula_keccak::{shake256, Shake256};
use macula_mldsa::{internal, ParameterSet, PrivateKey, ML_DSA_44, ML_DSA_65, ML_DSA_87};

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
    // SAFETY: the caller promises a live allocation of `size` bytes.
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

const SETS: [ParameterSet; 3] = [ML_DSA_44, ML_DSA_65, ML_DSA_87];

/// Random-looking bytes from a label, so no seed is a pattern like
/// `[1; 32]` that some unrelated buffer could hold by chance.
fn seed(label: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(label.as_bytes(), &mut out);
    out
}

/// `H(pieces..., len)`, worked out here rather than taken from the crate.
fn h(pieces: &[&[u8]], len: usize) -> Vec<u8> {
    let mut x = Shake256::new();
    for piece in pieces {
        x.update(piece);
    }
    let mut out = vec![0u8; len];
    x.finalize_xof().read(&mut out);
    out
}

/// One parameter set's inputs, and every secret its run must not leave on
/// the heap, worked out independently of the code under test where the
/// specification makes that possible.
struct Run {
    p: ParameterSet,
    xi: [u8; 32],
    sk: Vec<u8>,
    rnd: [u8; 32],
}

const MESSAGE: &[u8] = b"heap residue";
const CONTEXT: &[u8] = b"ctx";

impl Run {
    fn new(p: ParameterSet, needles: &mut Vec<(String, Vec<u8>)>) -> Run {
        let name = p.name;
        let xi = seed(&format!("{name} xi"));
        let rnd = seed(&format!("{name} rnd"));
        let (_, sk) = internal::key_gen(p, &xi);
        let sk = sk.to_vec();

        let mut add =
            |what: String, bytes: &[u8]| needles.push((format!("{name} {what}"), bytes.to_vec()));
        add("xi".into(), &xi);
        add("rnd".into(), &rnd);

        // Key generation: (rho, rho', K) = H(xi || k || l, 128).
        let seeds = h(&[&xi, &[p.k as u8, p.l as u8]], 128);
        add("rho'".into(), &seeds[32..96]);
        add("K".into(), &seeds[96..128]);
        assert_eq!(
            &sk[32..64],
            &seeds[96..128],
            "{name}: K worked out independently"
        );

        // The private key's secret bytes: s1, s2 and t0, packed.
        for (i, window) in sk[128..].as_chunks::<32>().0.iter().enumerate() {
            add(
                format!("sk secret bytes {}..{}", 128 + 32 * i, 160 + 32 * i),
                window,
            );
        }

        // Signing: mu = H(tr || 0 || |ctx| || ctx || M, 64), then
        // rho'' = H(K || rnd || mu, 64).
        let mu = h(
            &[&sk[64..128], &[0, CONTEXT.len() as u8], CONTEXT, MESSAGE],
            64,
        );
        add("rho''".into(), &h(&[&seeds[96..128], &rnd, &mu], 64));

        Run { p, xi, sk, rnd }
    }

    /// Every operation, with every output dropped before this returns.
    fn exercise(&self) {
        drop(internal::key_gen(self.p, &self.xi));
        for sk in [PrivateKey::Expanded(&self.sk), PrivateKey::Seed(&self.xi)] {
            drop(internal::sign_message(
                self.p, sk, MESSAGE, CONTEXT, &self.rnd,
            ));
        }
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
