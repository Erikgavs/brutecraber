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
fn banner_reports_the_cargo_package_version() {
    Command::cargo_bin("brutecraber")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(concat!("v", env!("CARGO_PKG_VERSION"))));
}

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
fn cli_help_documents_ambiguous_and_explicit_hash_formats() {
    Command::cargo_bin("brutecraber")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("MD5/NTLM"))
        .stdout(contains("colon-delimited"))
        .stdout(contains("md5-salt-suffix"));
}

#[test]
fn explicit_type_cracks_all_raw_hex_algorithms() {
    let cases = [
        ("md5", MD5_PASSWORD),
        ("sha1", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"),
        (
            "sha256",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        ),
        (
            "sha512",
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
        ),
        (
            "sha3-256",
            "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484",
        ),
        (
            "sha3-512",
            "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716",
        ),
    ];

    for (hash_type, digest) in cases {
        let inputs = TestInputs::new(
            format!("{digest}\n").as_bytes(),
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
fn auto_detects_and_cracks_sha1_and_ambiguous_sha2_sha3_hashes() {
    let cases = [
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484",
        "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
        "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716",
    ];

    for digest in cases {
        let inputs = TestInputs::new(
            format!("{digest}\n").as_bytes(),
            format!("{PASSWORD}\n").as_bytes(),
        );

        inputs
            .crack_command(None)
            .assert()
            .success()
            .stdout(contains("cracked 1/1 hashes"));
    }
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
fn bcrypt_cli_cracks_known_embedded_salt_hash() {
    let hash = "$2y$04$xa4SIvcnMqIWtM8LZt3/2eoi5AsfZdM.wstwCsGVXDHSVY6Egv9rm\n";
    let inputs = TestInputs::new(hash.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));

    inputs
        .crack_command(Some("bcrypt"))
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn argon2_cli_cracks_phc_fixture_in_auto_and_explicit_modes() {
    let hashes = fs::read_to_string("tests/hashes/argon2/hashes.txt").unwrap();
    let wordlist = fs::read_to_string("tests/hashes/argon2/wordlist.txt").unwrap();
    let inputs = TestInputs::new(hashes.as_bytes(), wordlist.as_bytes());

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("cracked 3/3 hashes"));

    inputs
        .crack_command(Some("argon2"))
        .assert()
        .success()
        .stdout(contains("cracked 3/3 hashes"));
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
fn cli_rules_can_crack_a_transformed_candidate() {
    let password_hash = "dc647eb65e6711e155375218212b3964";
    let inputs = TestInputs::new(
        format!("{password_hash}\n").as_bytes(),
        format!("{PASSWORD}\n").as_bytes(),
    );
    let mut command = inputs.crack_command(Some("md5"));
    command.arg("--rules");

    command
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
fn auto_ignores_comment_lines() {
    let hashes = format!("# hashes generated for this challenge\n{MD5_PASSWORD}\n");
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

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
fn base64_with_padding_still_cracks_with_explicit_type() {
    let hash = "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=\n";
    let inputs = TestInputs::new(hash.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .crack_command(Some("sha256-base64"))
        .assert()
        .success()
        .stdout(contains("cracked 1/1 hashes"));
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

#[test]
fn explicit_type_cracks_all_salt_prefix_algorithms() {
    let cases = [
        ("md5-salt", "86f75bc83edcd705c834c436f6b64fdc"),
        ("sha1-salt", "4b7f88df9bc5e48e1e5bd3ad9bb1cc54e54ba68d"),
        (
            "sha256-salt",
            "ab8182cc945620b02e1bca27accc51809b2a5fca67f576823c0044b09ee693c8",
        ),
        (
            "sha512-salt",
            "16840f66c91412ad31d522935d66b54d423c4f240aca10480cef20436a11d119e29ad82b761e8eafb8abf2bfabbe0aebb4732c76267225f6ad178d8896a9018f",
        ),
        (
            "sha3-256-salt",
            "a4b91e1006e60758ffe90df79580b5b15fd37ab6e6a49a8c03939beff5a61e3a",
        ),
        (
            "sha3-512-salt",
            "0154e9b9d5509ef2bf78fb2ac017a51d5c8ef9f7e4596eef7174bda271b93289a959878edc4a144a0943d9a18db6c77391089290747235f62a111958ed47b91a",
        ),
    ];

    for (hash_type, digest) in cases {
        let hashes = format!("x7k2:{digest}\n");
        let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

        inputs
            .crack_command(Some(hash_type))
            .assert()
            .success()
            .stdout(contains("cracked 1/1 hashes"));
    }
}

#[test]
fn duplicate_hashes_and_wordlist_entries_count_once() {
    let hashes = format!("{MD5_PASSWORD}\n{MD5_PASSWORD}\n");
    let words = format!("{PASSWORD}\n{PASSWORD}\n");
    let inputs = TestInputs::new(hashes.as_bytes(), words.as_bytes());

    let output = inputs
        .crack_command(Some("md5"))
        .output()
        .expect("run brutecraber");
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success());
    assert!(output_text.contains("cracked 1/1 hashes"));
    assert!(output_text.contains("ignored 1 duplicate hash record"));
}

#[test]
fn invalid_utf8_wordlist_is_rejected_without_lossy_conversion() {
    let inputs = TestInputs::new(format!("{MD5_PASSWORD}\n").as_bytes(), b"pass\xffword\n");

    inputs
        .crack_command(Some("md5"))
        .assert()
        .failure()
        .stderr(contains("wordlist must be valid UTF-8"));
}

#[test]
fn invalid_hash_records_are_reported_without_blocking_valid_records() {
    let hashes = format!("{MD5_PASSWORD}\nnot-a-hash\n");
    let inputs = TestInputs::new(hashes.as_bytes(), format!("{PASSWORD}\n").as_bytes());

    inputs
        .crack_command(None)
        .assert()
        .success()
        .stdout(contains("1 invalid hash record"))
        .stdout(contains("cracked 1/1 hashes"));
}

#[test]
fn unsupported_explicit_hash_type_returns_nonzero_status() {
    let inputs = TestInputs::new(
        format!("{MD5_PASSWORD}\n").as_bytes(),
        format!("{PASSWORD}\n").as_bytes(),
    );

    inputs
        .crack_command(Some("not-a-supported-type"))
        .assert()
        .failure()
        .stderr(contains("unsupported hash type"));
}
