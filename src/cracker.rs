use crate::hashes;
use base64::{Engine, engine::general_purpose};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::Mutex;

const VALID_HASH_TYPES: &[&str] = &[
    "md5",
    "md5/ntlm",
    "md5-base64",
    "md5-salt",
    "md5-salt-suffix",
    "sha1",
    "sha1-base64",
    "sha1-salt",
    "sha1-salt-suffix",
    "sha256",
    "sha256-base64",
    "sha256-salt",
    "sha256-salt-suffix",
    "sha512",
    "sha512-base64",
    "sha512-salt",
    "sha512-salt-suffix",
    "sha3-256",
    "sha3-256-base64",
    "sha3-256-salt",
    "sha3-256-salt-suffix",
    "sha256/sha3-256",
    "sha3-512",
    "sha3-512-base64",
    "sha3-512-salt",
    "sha3-512-salt-suffix",
    "sha512/sha3-512",
    "scrypt",
    "argon2",
    "bcrypt",
    "pbkdf2",
    "ntlm",
    "wpa-pmkid",
];

#[derive(Default)]
struct FoundHashes(Mutex<HashSet<String>>);

impl FoundHashes {
    fn insert(&self, target: String) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(target)
    }

    fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

fn report_found(found: &FoundHashes, key: String, bar: &ProgressBar, message: String) {
    if found.insert(key) {
        bar.println(message);
    }
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    // Validate even length (each byte = 2 hex chars)
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    // Iterate every 2 chars (0, 2, 4, 6...) and convert hex pairs to bytes
    // Example: "5f4d" -> ["5f", "4d"] -> [0x5f, 0x4d] -> [95, 77]
    let mut bytes = vec![0u8; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes).ok()?;
    Some(bytes)
}

fn hash_value(record: &str) -> &str {
    // An explicitly selected raw/KDF type may read `username:hash`; auto mode
    // rejects colon-delimited records because they can also represent salted hashes.
    record.rsplit_once(':').map_or(record, |(_, hash)| hash)
}

fn decode_base64_hash(hash: &str) -> Option<Vec<u8>> {
    // Base64 permits omitted padding in some generators; accept both encodings.
    general_purpose::STANDARD
        .decode(hash)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(hash))
        .ok()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_len_for_type(hash_type: &str) -> Option<usize> {
    match hash_type {
        "md5" | "md5/ntlm" | "ntlm" | "md5-base64" | "md5-salt" | "md5-salt-suffix" => Some(16),
        "sha1" | "sha1-base64" | "sha1-salt" | "sha1-salt-suffix" => Some(20),
        "sha256"
        | "sha256/sha3-256"
        | "sha3-256"
        | "sha256-base64"
        | "sha3-256-base64"
        | "sha256-salt"
        | "sha3-256-salt"
        | "sha256-salt-suffix"
        | "sha3-256-salt-suffix" => Some(32),
        "sha512"
        | "sha512/sha3-512"
        | "sha3-512"
        | "sha512-base64"
        | "sha3-512-base64"
        | "sha512-salt"
        | "sha3-512-salt"
        | "sha512-salt-suffix"
        | "sha3-512-salt-suffix" => Some(64),
        _ => None,
    }
}

pub fn target_key(hash_type: &str, record: &str) -> Option<String> {
    let value = hash_value(record);
    match hash_type {
        "bcrypt" => {
            return hashes::bcrypt::is_valid_hash_format(value).then(|| value.to_owned());
        }
        "argon2" => {
            return hashes::argon2::is_valid_hash_format(value).then(|| value.to_owned());
        }
        "scrypt" => {
            return hashes::scrypt::is_valid_hash_format(value).then(|| value.to_owned());
        }
        "pbkdf2" => {
            return hashes::pbkdf2::is_valid_hash_format(value).then(|| value.to_owned());
        }
        "wpa-pmkid" => {
            return hashes::wpa::is_valid_pmkid_line(record).then(|| record.to_owned());
        }
        _ => {}
    }

    let digest_len = digest_len_for_type(hash_type)?;

    if hash_type.ends_with("-salt-suffix") {
        let (target, salt) = record.split_once(':')?;
        let bytes = hex_to_bytes(target)?;
        return (bytes.len() == digest_len).then(|| format!("{}:{salt}", bytes_to_hex(&bytes)));
    }

    if hash_type.ends_with("-salt") {
        let (salt, target) = record.split_once(':')?;
        let bytes = hex_to_bytes(target)?;
        return (bytes.len() == digest_len).then(|| format!("{salt}:{}", bytes_to_hex(&bytes)));
    }

    if hash_type.ends_with("-base64") {
        let bytes = decode_base64_hash(hash_value(record))?;
        return (bytes.len() == digest_len).then(|| bytes_to_hex(&bytes));
    }

    let bytes = hex_to_bytes(hash_value(record))?;
    (bytes.len() == digest_len).then(|| bytes_to_hex(&bytes))
}

pub fn is_supported_hash_type(hash_type: &str) -> bool {
    VALID_HASH_TYPES.contains(&hash_type)
}

fn suffix_salted_hash(hash_type: &str, password: &str, salt: &str) -> Option<Vec<u8>> {
    // `*-salt-suffix` explicitly means hash(password + salt); `*-salt` remains salt + password.
    let candidate = format!("{password}{salt}");
    match hash_type {
        "md5-salt-suffix" => Some(hashes::md5::crack(&candidate).to_vec()),
        "sha1-salt-suffix" => Some(hashes::sha1_hash::crack(&candidate).to_vec()),
        "sha256-salt-suffix" => Some(hashes::sha256::crack(&candidate).to_vec()),
        "sha512-salt-suffix" => Some(hashes::sha512::crack(&candidate).to_vec()),
        "sha3-256-salt-suffix" => Some(hashes::sha3_256::crack(&candidate).to_vec()),
        "sha3-512-salt-suffix" => Some(hashes::sha3_512::crack(&candidate).to_vec()),
        _ => None,
    }
}

pub fn run(hashes: &[&str], wordlist: &str, hash_type: &str, rule: bool) -> usize {
    let star = "[*]";

    // BAR
    let total = wordlist.lines().count() as u64;
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("\n[{elapsed_precise}] [{bar:40}] {pos}/{len} ({percent}%)\n")
            .unwrap()
            .progress_chars("=> "),
    );

    // each thread waits to add a 1 (for example, in this case)
    let found = FoundHashes::default();

    if !is_supported_hash_type(hash_type) {
        bar.println(format!("\n{} unsupported type of hash", "[!]".red()));
        bar.finish();
        return 0;
    }

    if hash_type == "md5/ntlm" {
        let target_hashes: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |word| {
            let md5_hash = hashes::md5::crack(word);
            let matched_hash = if target_hashes.contains(&md5_hash) {
                Some(md5_hash)
            } else {
                let ntlm_hash = hashes::ntlm::crack(word);
                target_hashes.contains(&ntlm_hash).then_some(ntlm_hash)
            };

            if let Some(hash_bytes) = matched_hash {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, word),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "md5" {
        let hash_set: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::md5::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha1" {
        let hash_set: HashSet<[u8; 20]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha1_hash::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha256" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha512" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha3-256" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha3-512" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "ntlm" {
        let hash_set: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::ntlm::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "md5-base64" {
        let hash_set: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| decode_base64_hash(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::md5::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash decoded and cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha1-base64" {
        let hash_set: HashSet<[u8; 20]> = hashes
            .iter()
            .filter_map(|h| decode_base64_hash(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha1_hash::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash decoded and cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha256-base64" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| decode_base64_hash(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash decoded and cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha512-base64" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| decode_base64_hash(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash decoded and cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha3-256-base64" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| decode_base64_hash(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash decoded and cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha3-512-base64" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| decode_base64_hash(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash decoded and cracked {} -> {}", star.green(), hex, w),
                );
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "scrypt" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::scrypt::verify(w, hash_value(h)) {
                    report_found(
                        &found,
                        hash_value(h).to_owned(),
                        &bar,
                        format!("{} hash cracked {} -> {}", star.green(), h, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "md5-salt" {
        let salted_targets: Vec<(&str, [u8; 16])> = hashes
            .iter()
            .filter_map(|h| {
                let (salt, target) = h.split_once(':')?;
                let bytes: [u8; 16] = hex_to_bytes(target)?.try_into().ok()?;
                Some((salt, bytes))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            for (salt, target_bytes) in &salted_targets {
                let hash_bytes = hashes::md5::crack_with_salt(w, salt);
                if hash_bytes == *target_bytes {
                    let hex: String = target_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        format!("{salt}:{hex}"),
                        &bar,
                        format!(
                            "{} hash cracked [salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            hex,
                            w
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha1-salt" {
        let salted_targets: Vec<(&str, [u8; 20])> = hashes
            .iter()
            .filter_map(|h| {
                let (salt, target) = h.split_once(':')?;
                let bytes: [u8; 20] = hex_to_bytes(target)?.try_into().ok()?;
                Some((salt, bytes))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            for (salt, target_bytes) in &salted_targets {
                let hash_bytes = hashes::sha1_hash::crack_with_salt(w, salt);
                if hash_bytes == *target_bytes {
                    let hex: String = target_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        format!("{salt}:{hex}"),
                        &bar,
                        format!(
                            "{} hash cracked [salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            hex,
                            w
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha256-salt" {
        let salted_targets: Vec<(&str, [u8; 32])> = hashes
            .iter()
            .filter_map(|h| {
                let (salt, target) = h.split_once(':')?;
                let bytes: [u8; 32] = hex_to_bytes(target)?.try_into().ok()?;
                Some((salt, bytes))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            for (salt, target_bytes) in &salted_targets {
                let hash_bytes = hashes::sha256::crack_with_salt(w, salt);
                if hash_bytes == *target_bytes {
                    let hex: String = target_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        format!("{salt}:{hex}"),
                        &bar,
                        format!(
                            "{} hash cracked [salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            hex,
                            w
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha512-salt" {
        let salted_targets: Vec<(&str, [u8; 64])> = hashes
            .iter()
            .filter_map(|h| {
                let (salt, target) = h.split_once(':')?;
                let bytes: [u8; 64] = hex_to_bytes(target)?.try_into().ok()?;
                Some((salt, bytes))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            for (salt, target_bytes) in &salted_targets {
                let hash_bytes = hashes::sha512::crack_with_salt(w, salt);
                if hash_bytes == *target_bytes {
                    let hex: String = target_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        format!("{salt}:{hex}"),
                        &bar,
                        format!(
                            "{} hash cracked [salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            hex,
                            w
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha3-256-salt" {
        let salted_targets: Vec<(&str, [u8; 32])> = hashes
            .iter()
            .filter_map(|h| {
                let (salt, target) = h.split_once(':')?;
                let bytes: [u8; 32] = hex_to_bytes(target)?.try_into().ok()?;
                Some((salt, bytes))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            for (salt, target_bytes) in &salted_targets {
                let hash_bytes = hashes::sha3_256::crack_with_salt(w, salt);
                if hash_bytes == *target_bytes {
                    let hex: String = target_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        format!("{salt}:{hex}"),
                        &bar,
                        format!(
                            "{} hash cracked [salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            hex,
                            w
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha3-512-salt" {
        let salted_targets: Vec<(&str, [u8; 64])> = hashes
            .iter()
            .filter_map(|h| {
                let (salt, target) = h.split_once(':')?;
                let bytes: [u8; 64] = hex_to_bytes(target)?.try_into().ok()?;
                Some((salt, bytes))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            for (salt, target_bytes) in &salted_targets {
                let hash_bytes = hashes::sha3_512::crack_with_salt(w, salt);
                if hash_bytes == *target_bytes {
                    let hex: String = target_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        format!("{salt}:{hex}"),
                        &bar,
                        format!(
                            "{} hash cracked [salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            hex,
                            w
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type.ends_with("-salt-suffix") {
        let salted_targets: Vec<(&str, Vec<u8>)> = hashes
            .iter()
            .filter_map(|line| {
                let (target, salt) = line.split_once(':')?;
                Some((salt, hex_to_bytes(target)?))
            })
            .collect();

        parallel_crack(wordlist, rule, &bar, |word| {
            for (salt, target_bytes) in &salted_targets {
                if suffix_salted_hash(hash_type, word, salt).as_deref()
                    == Some(target_bytes.as_slice())
                {
                    let target_hex = bytes_to_hex(target_bytes);
                    report_found(
                        &found,
                        format!("{target_hex}:{salt}"),
                        &bar,
                        format!(
                            "{} hash cracked [suffix salt:{}] {} -> {}",
                            star.green(),
                            salt,
                            target_hex,
                            word
                        ),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha256/sha3-256" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            } else {
                let hash_bytes = hashes::sha3_256::crack(w);
                if hash_set.contains(&hash_bytes) {
                    let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        hex.clone(),
                        &bar,
                        format!("{} hash cracked {} -> {}", star.green(), hex, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "sha512/sha3-512" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(hash_value(h))?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                report_found(
                    &found,
                    hex.clone(),
                    &bar,
                    format!("{} hash cracked {} -> {}", star.green(), hex, w),
                );
            } else {
                let hash_bytes = hashes::sha3_512::crack(w);
                if hash_set.contains(&hash_bytes) {
                    let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    report_found(
                        &found,
                        hex.clone(),
                        &bar,
                        format!("{} hash cracked {} -> {}", star.green(), hex, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "bcrypt" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::bcrypt::crack(w, hash_value(h)) {
                    report_found(
                        &found,
                        hash_value(h).to_owned(),
                        &bar,
                        format!("{} hash cracked {} -> {}", star.green(), h, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "pbkdf2" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::pbkdf2::verify(w, hash_value(h)) {
                    report_found(
                        &found,
                        hash_value(h).to_owned(),
                        &bar,
                        format!("{} hash cracked {} -> {}", star.green(), h, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "wpa-pmkid" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if crate::hashes::wpa::verify_pmkid_line(w, h) {
                    report_found(
                        &found,
                        (*h).to_owned(),
                        &bar,
                        format!("{} PMKID cracked {} -> {}", star.green(), h, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    if hash_type == "argon2" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::argon2::verify(w, hash_value(h)) {
                    report_found(
                        &found,
                        hash_value(h).to_owned(),
                        &bar,
                        format!("{} hash cracked {} -> {}", star.green(), h, w),
                    );
                }
            }
        });
        bar.finish();
        return found.len();
    }

    bar.finish();
    found.len()
}

fn parallel_crack<F>(wordlist: &str, rule: bool, bar: &ProgressBar, matcher: F)
where
    F: Fn(&str) + Sync + Send,
{
    const CHUNK_SIZE: usize = 64;

    let lines: Vec<&str> = wordlist.lines().collect();

    lines.par_chunks(CHUNK_SIZE).for_each(|chunk| {
        bar.inc(chunk.len() as u64);

        for word in chunk {
            if rule {
                for w in crate::rules::apply(word) {
                    matcher(&w);
                }
            } else {
                matcher(word);
            }
        }
    });
}
