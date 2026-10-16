use assert_cmd::Command;
use predicates::str::contains;

fn bin() -> Command {
    Command::cargo_bin("brutecraber").unwrap()
}

#[test]
fn detects_pmkid_hashes() {
    bin()
        .args(["--detect-hash", "tests/hashes/wpa-pmkid/hashes.txt"])
        .assert()
        .success()
        .stdout(contains("hash detected: wpa-pmkid"));
}

#[test]
fn cracks_pmkid_hashes_with_cpu_and_auto_detection() {
    bin()
        .args([
            "-f",
            "tests/hashes/wpa-pmkid/hashes.txt",
            "-w",
            "tests/hashes/wpa-pmkid/wordlist.txt",
            "--cpu",
        ])
        .assert()
        .success()
        .stdout(contains("Auto detected hash: wpa-pmkid"))
        .stdout(contains("cracked 3/3 hashes"));
}
