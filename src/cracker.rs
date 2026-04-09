use crate::hashes;
use base64::{Engine, engine::general_purpose};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    let found = AtomicUsize::new(0);

    let valid_types = [
        "md5",
        "md5-base64",
        "md5-salt",
        "sha1",
        "sha1-base64",
        "sha1-salt",
        "sha256",
        "sha256-base64",
        "sha256-salt",
        "sha512",
        "sha512-base64",
        "sha512-salt",
        "sha3-256",
        "sha3-256-base64",
        "sha3-256-salt",
        "sha256/sha3-256",
        "sha3-512",
        "sha3-512-base64",
        "sha3-512-salt",
        "sha512/sha3-512",
        "scrypt",
        "argon2",
        "bcrypt",
        "ntlm",
    ];

    if !valid_types.contains(&hash_type) {
        bar.println(format!("\n{} unsupported type of hash", "[!]".red()));
        bar.finish();
        return 0;
    }

    if hash_type == "md5" {
        let hash_set: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::md5::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha1" {
        let hash_set: HashSet<[u8; 20]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha1_hash::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha256" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha512" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-256" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-512" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "ntlm" {
        let hash_set: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::ntlm::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "md5-base64" {
        let hash_set: HashSet<[u8; 16]> = hashes
            .iter()
            .filter_map(|h| general_purpose::STANDARD.decode(h).ok()?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::md5::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!(
                    "{} hash decoded and cracked {} -> {}",
                    star.green(),
                    hex,
                    w
                ));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha1-base64" {
        let hash_set: HashSet<[u8; 20]> = hashes
            .iter()
            .filter_map(|h| general_purpose::STANDARD.decode(h).ok()?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha1_hash::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!(
                    "{} hash decoded and cracked {} -> {}",
                    star.green(),
                    hex,
                    w
                ));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha256-base64" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| general_purpose::STANDARD.decode(h).ok()?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!(
                    "{} hash decoded and cracked {} -> {}",
                    star.green(),
                    hex,
                    w
                ));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha512-base64" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| general_purpose::STANDARD.decode(h).ok()?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!(
                    "{} hash decoded and cracked {} -> {}",
                    star.green(),
                    hex,
                    w
                ));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-256-base64" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| general_purpose::STANDARD.decode(h).ok()?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!(
                    "{} hash decoded and cracked {} -> {}",
                    star.green(),
                    hex,
                    w
                ));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-512-base64" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| general_purpose::STANDARD.decode(h).ok()?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha3_512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!(
                    "{} hash decoded and cracked {} -> {}",
                    star.green(),
                    hex,
                    w
                ));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "scrypt" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::scrypt::verify(w, h) {
                    bar.println(format!("{} hash cracked {} -> {}", star.green(), h, w));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
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
                    bar.println(format!(
                        "{} hash cracked [salt:{}] {} -> {}",
                        star.green(),
                        salt,
                        hex,
                        w
                    ));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
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
                    bar.println(format!(
                        "{} hash cracked [salt:{}] {} -> {}",
                        star.green(),
                        salt,
                        hex,
                        w
                    ));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
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
                    bar.println(format!(
                        "{} hash cracked [salt:{}] {} -> {}",
                        star.green(),
                        salt,
                        hex,
                        w
                    ));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
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
                    bar.println(format!(
                        "{} hash cracked [salt:{}] {} -> {}",
                        star.green(),
                        salt,
                        hex,
                        w
                    ));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
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
                    bar.println(format!(
                        "{} hash cracked [salt:{}] {} -> {}",
                        star.green(),
                        salt,
                        hex,
                        w
                    ));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
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
                    bar.println(format!(
                        "{} hash cracked [salt:{}] {} -> {}",
                        star.green(),
                        salt,
                        hex,
                        w
                    ));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha256/sha3-256" {
        let hash_set: HashSet<[u8; 32]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha256::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            } else {
                let hash_bytes = hashes::sha3_256::crack(w);
                if hash_set.contains(&hash_bytes) {
                    let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha512/sha3-512" {
        let hash_set: HashSet<[u8; 64]> = hashes
            .iter()
            .filter_map(|h| hex_to_bytes(h)?.try_into().ok())
            .collect();

        parallel_crack(wordlist, rule, &bar, |w| {
            let hash_bytes = hashes::sha512::crack(w);
            if hash_set.contains(&hash_bytes) {
                let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                found.fetch_add(1, Ordering::Relaxed);
            } else {
                let hash_bytes = hashes::sha3_512::crack(w);
                if hash_set.contains(&hash_bytes) {
                    let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    bar.println(format!("{} hash cracked {} -> {}", star.green(), hex, w));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "bcrypt" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::bcrypt::crack(w, h) {
                    bar.println(format!("{} hash cracked {} -> {}", star.green(), h, w));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "argon2" {
        parallel_crack(wordlist, rule, &bar, |w| {
            for h in hashes {
                if hashes::argon2::verify(w, h) {
                    bar.println(format!("{} hash cracked {} -> {}", star.green(), h, w));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    bar.finish();
    found.load(Ordering::Relaxed)
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
