use assert_cmd::Command;
use predicates::str::contains;

fn bin() -> Command {
    Command::cargo_bin("brutecraber").unwrap()
}

fn crack_fixture(hashes: &str, wordlist: &str, hash_type: Option<&str>) -> Command {
    let mut command = bin();
    command.args(["-f", hashes, "-w", wordlist, "--cpu", "-j", "1"]);

    if let Some(hash_type) = hash_type {
        command.args(["-t", hash_type]);
    }

    command
}

#[test]
fn auto_detects_and_cracks_scrypt_phc_fixture() {
    crack_fixture(
        "tests/hashes/scrypt/hashes.txt",
        "tests/hashes/scrypt/wordlist.txt",
        None,
    )
    .assert()
    .success()
    .stdout(contains("Auto detected hash: scrypt"))
    .stdout(contains("cracked 3/3 hashes"));
}

#[test]
fn explicit_scrypt_type_cracks_phc_fixture() {
    crack_fixture(
        "tests/hashes/scrypt/hashes.txt",
        "tests/hashes/scrypt/wordlist.txt",
        Some("scrypt"),
    )
    .assert()
    .success()
    .stdout(contains("cracked 3/3 hashes"));
}

#[test]
fn auto_detects_and_cracks_pbkdf2_phc_fixture() {
    crack_fixture(
        "tests/hashes/pbkdf2/hashes.txt",
        "tests/hashes/pbkdf2/wordlist.txt",
        None,
    )
    .assert()
    .success()
    .stdout(contains("Auto detected hash: pbkdf2"))
    .stdout(contains("cracked 3/3 hashes"));
}

#[test]
fn explicit_pbkdf2_type_cracks_phc_fixture() {
    crack_fixture(
        "tests/hashes/pbkdf2/hashes.txt",
        "tests/hashes/pbkdf2/wordlist.txt",
        Some("pbkdf2"),
    )
    .assert()
    .success()
    .stdout(contains("cracked 3/3 hashes"));
}
