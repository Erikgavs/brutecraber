use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

struct TestInputs {
    directory: PathBuf,
    hashes: PathBuf,
    wordlist: PathBuf,
}

impl TestInputs {
    fn new(hashes: &[u8], wordlist: &[u8]) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "brutecraber-hash-regression-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create temporary test directory");

        let hash_path = directory.join("hashes.txt");
        let wordlist_path = directory.join("wordlist.txt");
        fs::write(&hash_path, hashes).expect("write temporary hash file");
        fs::write(&wordlist_path, wordlist).expect("write temporary wordlist");

        Self {
            directory,
            hashes: hash_path,
            wordlist: wordlist_path,
        }
    }

    fn crack_command(&self, hash_type: Option<&str>) -> Command {
        let mut command = Command::cargo_bin("brutecraber").unwrap();
        command
            .arg("-f")
            .arg(&self.hashes)
            .arg("-w")
            .arg(&self.wordlist)
            .args(["--cpu", "-j", "1"]);

        if let Some(hash_type) = hash_type {
            command.args(["-t", hash_type]);
        }

        command
    }

    fn detect_command(&self) -> Command {
        let mut command = Command::cargo_bin("brutecraber").unwrap();
        command.arg("--detect-hash").arg(&self.hashes);
        command
    }
}

impl Drop for TestInputs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

const PASSWORD: &str = "password";
const MD5_PASSWORD: &str = "5f4dcc3b5aa765d61d8327deb882cf99";
const NTLM_PASSWORD: &str = "8846f7eaee8fb117ad06bdd830b7586c";

#[test]
fn auto_cracks_md5_32_hex_hash() {
    let inputs = TestInputs::new(
        format!("{MD5_PASSWORD}\n").as_bytes(),
        format!("{PASSWORD}\n").as_bytes(),
    );

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn explicit_ntlm_cracks_the_32_hex_known_vector() {
    let inputs = TestInputs::new(
        format!("{NTLM_PASSWORD}\n").as_bytes(),
        format!("{PASSWORD}\n").as_bytes(),
    );

    inputs
        .crack_command(Some("ntlm"))
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn explicit_raw_type_accepts_username_hash_records() {
    let hashes = format!("alice:{MD5_PASSWORD}\n");
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .crack_command(Some("md5"))
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn auto_requires_explicit_type_for_colon_delimited_records() {
    let hashes = format!("alice:{MD5_PASSWORD}\n");
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .detect_command()
        .assert()
        .success()
        .stdout(contains("colon-delimited"));

    inputs
        .crack_command(None)
        .assert()
        .failure()
        .stderr(contains("colon-delimited"));
}

#[test]
fn auto_cracks_ntlm_instead_of_assuming_md5() {
    let inputs = TestInputs::new(
        format!("{NTLM_PASSWORD}\n").as_bytes(),
        format!("{PASSWORD}\n").as_bytes(),
    );

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn detector_reports_32_hex_hashes_as_ambiguous() {
    let inputs = TestInputs::new(
        format!("{MD5_PASSWORD}\n").as_bytes(),
        format!("{PASSWORD}\n").as_bytes(),
    );

    inputs
        .detect_command()
        .assert()
        .success()
        .stdout(contains("ambiguous"));
}

#[test]
fn auto_rejects_mixed_hash_types_before_partial_cracking() {
    let sha1_password = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    let hashes = format!("{MD5_PASSWORD}\n{sha1_password}\n");
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .crack_command(None)
        .assert()
        .failure()
        .stderr(contains("mixed"));
}

#[test]
fn auto_skips_leading_blank_lines_consistently() {
    let hashes = format!("\n{MD5_PASSWORD}\n");
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .detect_command()
        .assert()
        .success()
        .stdout(contains("hash detected: md5/ntlm (ambiguous)"));

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn auto_strips_utf8_bom_from_hash_file() {
    let mut hashes = vec![0xEF, 0xBB, 0xBF];
    hashes.extend_from_slice(MD5_PASSWORD.as_bytes());
    hashes.push(b'\n');
    let inputs = TestInputs::new(&hashes, format!("{PASSWORD}\n").as_bytes());

    inputs
        .detect_command()
        .assert()
        .success()
        .stdout(contains("hash detected: md5/ntlm (ambiguous)"));

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn auto_detects_and_cracks_pbkdf2_phc_hashes() {
    // Independent PBKDF2-HMAC-SHA256 vector: password, salt "audit-salt", 10,000 rounds.
    let hash =
        "$pbkdf2-sha256$i=10000$YXVkaXQtc2FsdA$rlCpYVsfpV0syC+bwHqAJ0v4f47/VWJDeWWAtIzDths\n";
    let inputs = TestInputs::new(hash.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .detect_command()
        .assert()
        .success()
        .stdout(contains("hash detected: pbkdf2"));

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn base64_without_padding_cracks_with_explicit_type() {
    let cases = [
        ("md5-base64", "X03MO1qnZdYdgyfeuILPmQ"),
        ("sha1-base64", "W6ph5Mm5Pz8GgiULbPgzG37mj9g"),
        (
            "sha256-base64",
            "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg",
        ),
        (
            "sha512-base64",
            "sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg",
        ),
        (
            "sha3-256-base64",
            "wAZ9SvTofwDbrGO2FWgoI3BZFy0bvqxnQnNF1qn9pIQ",
        ),
        (
            "sha3-512-base64",
            "6adUhnNqVQr0/qhh4jeDBcSlVaBQlN7h3KL2iv6knMOlDo3m6hMepSExH01vsFShRugoL441/y5jaMGmLpCXFg",
        ),
    ];

    for (hash_type, encoded_hash) in cases {
        let inputs = TestInputs::new(
            format!("{encoded_hash}\n").as_bytes(),
            format!("{PASSWORD}\n").as_bytes(),
        );

        inputs
            .crack_command(Some(hash_type))
            .assert()
            .success()
            .stdout(contains("cracked 1/1 hashes"));
    }
}

#[test]
fn hash_salt_layout_uses_explicit_suffix_salt_types() {
    let cases = [
        ("md5-salt-suffix", "9af87eabc21c318d6839aea39d5156bb"),
        (
            "sha1-salt-suffix",
            "9e05c7feea76393d4758834df1203f902b661302",
        ),
        (
            "sha256-salt-suffix",
            "80dd89ecd29cd39ac3fdf5b125d90a8bd436b8cdb203f1bbd3ed2bee284ea707",
        ),
        (
            "sha512-salt-suffix",
            "f598bfe5b1b2fc22dd6f3e1768177e53816ceb86c2e11af67c3c546be2ed286c8aeb326bef4440f8e3a331e59ac375c35744ac0a165d4e41ae09d76cb2ae338b",
        ),
        (
            "sha3-256-salt-suffix",
            "9f3ebb0e6cad9d1374cde0b1c28c671f567887ac9e346f4d6c2b8a784fa1a47a",
        ),
        (
            "sha3-512-salt-suffix",
            "b9ff3d18f13d7fa4c65821fca318c790d2c6f6053dac8e9fec2fe19ffbe2a9e305f3d9221529440b92c8c66e71fd7e26c4e09d36ae65a6032de4b19391e09859",
        ),
    ];

    for (hash_type, digest) in cases {
        let inputs = TestInputs::new(
            format!("{digest}:x7k2\n").as_bytes(),
            format!("{PASSWORD}\n").as_bytes(),
        );

        inputs
            .crack_command(Some(hash_type))
            .assert()
            .success()
            .stdout(contains("cracked 1/1 hashes"));
    }
}

#[test]
fn existing_salt_hash_layout_remains_supported() {
    let hashes = "x7k2:86f75bc83edcd705c834c436f6b64fdc\n";
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .crack_command(Some("md5-salt"))
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}
