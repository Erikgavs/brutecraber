use assert_cmd::Command;
use predicates::str::contains;

fn bin() -> Command {
    Command::cargo_bin("brutecraber").unwrap()
}

#[test]
fn detects_md5() {
    bin()
        .args(["--detect-hash", "tests/hashes/md5/hashes.txt"])
        .assert()
        .success()
        .stdout(contains("hash detected: md5"));
}

#[test]
fn detects_sha256() {
    bin()
        .args(["--detect-hash", "tests/hashes/sha256/hashes.txt"])
        .assert()
        .success()
        .stdout(contains("hash detected: sha256/sha3-256"));
}

#[test]
fn detects_sha512() {
    bin()
        .args(["--detect-hash", "tests/hashes/sha512/hashes.txt"])
        .assert()
        .success()
        .stdout(contains("hash detected: sha512/sha3-512"));
}

#[test]
fn detects_mixed() {
    use std::io::Write;
    let mut tmp = std::env::temp_dir();
    tmp.push("brutecraber_mixed_test.txt");
    {
        let md5 = std::fs::read_to_string("tests/hashes/md5/hashes.txt").unwrap();
        let sha = std::fs::read_to_string("tests/hashes/sha256/hashes.txt").unwrap();
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(md5.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        f.write_all(sha.as_bytes()).unwrap();
    }

    bin()
        .args(["--detect-hash", tmp.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("hash detected: mixed"));
}
