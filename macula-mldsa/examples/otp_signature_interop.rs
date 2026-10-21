//! Interop between `macula-mldsa` and OTP's own `crypto`, the ML-DSA the
//! fleet's existing node keys were made with.
//!
//! Run with `scripts/otp-interop.sh`, which needs OTP 28.4 or later. Not
//! part of `scripts/test.sh`: CI has no OTP of that version.
//!
//! # What must agree, and how it is shown
//!
//! Signing is hedged on both sides, so no two signatures are ever the
//! same bytes, and no case compares signatures. What must agree exactly:
//!
//! - **The public key of one private key.** OTP generates a key and this
//!   crate derives its public key from the expanded form; this crate
//!   generates one and OTP derives it. Both must be byte-identical.
//! - **Each side's signatures verify on the other**, with the key expanded
//!   and, where OTP can sign with it, as its 32-byte seed. OTP cannot derive
//!   a public key from a seed, so a seed-signed signature is checked
//!   against the public key this crate derived from that seed: it verifies
//!   only if both expand the seed alike.
//!
//! OTP signs with an empty context string, which is all it can do, so this
//! crate signs and verifies with an empty context here too.
//!
//! # Negative controls
//!
//! A signature on one message must fail on another, on both sides; and a
//! signature this crate makes under a non-empty context must fail in OTP,
//! which assumes an empty one. If any is accepted, the checks above prove
//! nothing and the run exits 2.
//!
//! Exit codes: 0 every case as expected; 1 an interop case failed; 2 a
//! negative control failed; 3 this OTP cannot run the check.

use std::path::{Path, PathBuf};
use std::process::Command;

use macula_mldsa::{
    internal, public_key, sign, verify, ParameterSet, PrivateKey, ML_DSA_44, ML_DSA_65, ML_DSA_87,
};

const SETS: [(ParameterSet, &str); 3] = [
    (ML_DSA_44, "mldsa44"),
    (ML_DSA_65, "mldsa65"),
    (ML_DSA_87, "mldsa87"),
];

fn main() {
    let otp_bin = PathBuf::from(std::env::var("OTP_BIN").expect("OTP_BIN: OTP's bin directory"));
    let (release, crypto_lib) = otp_facts(&otp_bin);
    println!("OTP {release}, crypto library {crypto_lib}, against macula-mldsa\n");

    let dir = std::env::temp_dir().join(format!("macula-mldsa-otp-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let otp = Otp {
        escript: otp_bin.join("escript"),
        script: PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/otp_mldsa_peer.escript"
        )),
        dir: dir.clone(),
    };

    let mut cases = Cases::default();
    for (p, alg) in SETS {
        println!("{}", p.name);
        let keys = one_set(p, alg, &otp, &mut cases);
        we_sign_otp_verifies(p, alg, &otp, &keys, &mut cases);
        println!();
    }
    let _ = std::fs::remove_dir_all(&dir);

    if cases.control_failed {
        println!("NEGATIVE CONTROL FAILED: a signature was accepted where it must not be.");
        std::process::exit(2);
    }
    if cases.interop_failed {
        println!("INTEROP FAILED: see the cases marked FAIL.");
        std::process::exit(1);
    }
    println!("macula-mldsa and OTP's crypto agree on public keys and on each other's signatures, at all three sets.");
}

/// The tally of one run: an interop case, and a negative control that must
/// not be accepted.
#[derive(Default)]
struct Cases {
    interop_failed: bool,
    control_failed: bool,
}

impl Cases {
    fn check(&mut self, name: &str, pass: bool, control: bool) {
        println!("  {name:<66} {}", if pass { "PASS" } else { "FAIL" });
        if control {
            self.control_failed |= !pass;
            return;
        }
        self.interop_failed |= !pass;
    }
}

/// Both keys of one set, and the checks that each side derives the other's
/// public key.
struct Keys {
    pk_otp: Vec<u8>,
    sk_otp: Vec<u8>,
    pk_ours: Vec<u8>,
    seed: [u8; 32],
}

/// One set: the two keys, the public keys that must agree, and OTP signing
/// what this crate verifies.
fn one_set(p: ParameterSet, alg: &str, otp: &Otp, cases: &mut Cases) -> Keys {
    let msg = format!("{} interop", p.name).into_bytes();
    let other = b"another message".to_vec();

    // An OTP key: its public key, derived here from the expanded form.
    let (pk_otp, sk_otp) = otp.keygen(alg);
    cases.check(
        "OTP key: public key derived here from its expanded form matches",
        public_key(p, PrivateKey::Expanded(&sk_otp)).as_deref() == Ok(&pk_otp[..]),
        false,
    );

    // A key of ours: its public key, derived by OTP from the expanded form.
    let seed = [0x6du8; 32];
    let (pk_ours, sk_ours) = internal::key_gen(p, &seed);
    cases.check(
        "our key: public key derived by OTP from its expanded form matches",
        otp.derive(alg, &sk_ours) == pk_ours,
        false,
    );

    // OTP signs; we verify.
    let sig = otp.sign(alg, "expandedkey", &sk_otp, &msg);
    cases.check(
        "OTP signs with its key, we verify",
        verify(p, &pk_otp, &msg, &sig, b"") == Ok(true),
        false,
    );
    cases.check(
        "  ... and refuse it on another message",
        verify(p, &pk_otp, &other, &sig, b"") == Ok(false),
        true,
    );
    let sig = otp.sign(alg, "expandedkey", &sk_ours, &msg);
    cases.check(
        "OTP signs with our key expanded, we verify",
        verify(p, &pk_ours, &msg, &sig, b"") == Ok(true),
        false,
    );
    let sig = otp.sign(alg, "seed", &seed, &msg);
    cases.check(
        "OTP signs with our key's seed, we verify under our derived key",
        verify(p, &pk_ours, &msg, &sig, b"") == Ok(true),
        false,
    );

    Keys {
        pk_otp,
        sk_otp,
        pk_ours,
        seed,
    }
}

/// One set, the other way round: this crate signs and OTP verifies, with
/// the negative controls that make those cases mean anything.
fn we_sign_otp_verifies(p: ParameterSet, alg: &str, otp: &Otp, keys: &Keys, cases: &mut Cases) {
    let msg = format!("{} interop", p.name).into_bytes();
    let other = b"another message".to_vec();

    let sig = sign(p, PrivateKey::Expanded(&keys.sk_otp), &msg, b"").unwrap();
    cases.check(
        "we sign with OTP's key, OTP verifies",
        otp.verify(alg, &keys.pk_otp, &msg, &sig),
        false,
    );
    cases.check(
        "  ... and refuses it on another message",
        !otp.verify(alg, &keys.pk_otp, &other, &sig),
        true,
    );
    let sig = sign(p, PrivateKey::Seed(&keys.seed), &msg, b"").unwrap();
    cases.check(
        "we sign with our key as its seed, OTP verifies",
        otp.verify(alg, &keys.pk_ours, &msg, &sig),
        false,
    );
    let sig = sign(p, PrivateKey::Seed(&keys.seed), &msg, b"ctx").unwrap();
    cases.check(
        "  ... and refuses one made under a context it cannot see",
        !otp.verify(alg, &keys.pk_ours, &msg, &sig),
        true,
    );
}

/// The OTP release and the library its `crypto` is built on, checked for
/// the three ML-DSA sets before anything runs.
fn otp_facts(otp_bin: &Path) -> (String, String) {
    let out = Command::new(otp_bin.join("erl"))
        .args([
            "-noshell",
            "-eval",
            r#"
            Needed = [mldsa44, mldsa65, mldsa87],
            Missing = Needed -- proplists:get_value(public_keys, crypto:supports()),
            {ok, V} = file:read_file(filename:join([code:root_dir(), "releases",
                                     erlang:system_info(otp_release), "OTP_VERSION"])),
            [{Lib, _, Name}] = crypto:info_lib(),
            io:format("~s~n~s ~s~n~p~n", [string:trim(V), Lib, Name, Missing]),
            halt()."#,
        ])
        .output()
        .expect("run OTP's erl");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    if !out.status.success() || lines.len() < 3 {
        eprintln!(
            "cannot query OTP at {}:\n{text}{}",
            otp_bin.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        std::process::exit(3);
    }
    if lines[2] != "[]" {
        eprintln!(
            "OTP {} lacks ML-DSA sets this check needs: {}",
            lines[0], lines[2]
        );
        std::process::exit(3);
    }
    (lines[0].to_string(), lines[1].to_string())
}

/// OTP's side, one escript run per operation, with every value passed
/// through a file as raw bytes.
struct Otp {
    escript: PathBuf,
    script: PathBuf,
    dir: PathBuf,
}

impl Otp {
    fn run(&self, args: &[&str]) -> String {
        let out = Command::new(&self.escript)
            .arg(&self.script)
            .args(args)
            .output()
            .expect("run OTP's escript");
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(out.status.success(), "OTP {args:?}: {text}");
        text
    }

    fn file(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }

    fn put(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.file(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn get(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.file(name)).unwrap()
    }

    fn keygen(&self, alg: &str) -> (Vec<u8>, Vec<u8>) {
        self.run(&["keygen", alg, &self.file("pk"), &self.file("sk")]);
        (self.get("pk"), self.get("sk"))
    }

    fn derive(&self, alg: &str, sk: &[u8]) -> Vec<u8> {
        let sk_in = self.put("sk-in", sk);
        self.run(&["derive", alg, &sk_in, &self.file("pk-derived")]);
        self.get("pk-derived")
    }

    fn sign(&self, alg: &str, form: &str, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let key_in = self.put("key-in", key);
        let msg_in = self.put("msg-in", msg);
        self.run(&["sign", alg, form, &key_in, &msg_in, &self.file("sig")]);
        self.get("sig")
    }

    fn verify(&self, alg: &str, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let pk_in = self.put("pk-in", pk);
        let msg_in = self.put("msg-in", msg);
        let sig_in = self.put("sig-in", sig);
        match self
            .run(&["verify", alg, &pk_in, &msg_in, &sig_in])
            .as_str()
        {
            "valid" => true,
            "invalid" => false,
            other => panic!("OTP verify said {other:?}"),
        }
    }
}
