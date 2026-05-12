use assert_cmd::Command;
use predicates::str::contains;

fn bin() -> Command {
    Command::cargo_bin("brutecraber").unwrap()
}

#[test]
fn jobs_flag_accepted_with_one_thread() {
    bin()
        .args([
            "-f",
            "tests/hashes/md5/hashes.txt",
            "-w",
            "tests/wordlists/wordlist.txt",
            "--cpu",
            "-j",
            "1",
        ])
        .assert()
        .success()
        .stdout(contains("cracked"));
}

#[test]
fn jobs_flag_accepted_with_multiple_threads() {
    bin()
        .args([
            "-f",
            "tests/hashes/md5/hashes.txt",
            "-w",
            "tests/wordlists/wordlist.txt",
            "--cpu",
            "-j",
            "4",
        ])
        .assert()
        .success()
        .stdout(contains("cracked"));
}

#[test]
fn no_jobs_flag_still_works() {
    bin()
        .args([
            "-f",
            "tests/hashes/md5/hashes.txt",
            "-w",
            "tests/wordlists/wordlist.txt",
            "--cpu",
        ])
        .assert()
        .success()
        .stdout(contains("cracked"));
}
