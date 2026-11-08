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
        .stdout(contains("hash detected: md5"));

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
        .stdout(contains("hash detected: md5"));

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
