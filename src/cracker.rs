use crate::hashes;
use base64::{engine::general_purpose, Engine};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

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
        "bcrypt",
        "ntlm",
    ];

    if !valid_types.contains(&hash_type) {
        bar.println(format!("\n{} unsupported type of hash", "[!]".red()));
        bar.finish();
        return 0;
    }

    if hash_type == "md5" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::md5::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha1" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha1_hash::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha256" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha256::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha512" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha512::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-256" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha3_256::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-512" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha3_512::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "ntlm" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::ntlm::crack(w);
            if hashes.contains(&hash.as_str()) {
                bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                found.fetch_add(1, Ordering::Relaxed);
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "md5-base64" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::md5::crack(w);
            for h in hashes {
                if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                    let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                    if hex == hash {
                        bar.println(format!(
                            "{} hash decoded and cracked {} -> {} -> {}",
                            star.green(),
                            h,
                            hex,
                            w
                        ));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha1-base64" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha1_hash::crack(w);
            for h in hashes {
                if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                    let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                    if hex == hash {
                        bar.println(format!(
                            "{} hash decoded and cracked {} -> {} -> {}",
                            star.green(),
                            h,
                            hex,
                            w
                        ));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha256-base64" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha256::crack(w);
            for h in hashes {
                if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                    let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                    if hex == hash {
                        bar.println(format!(
                            "{} hash decoded and cracked {} -> {} -> {}",
                            star.green(),
                            h,
                            hex,
                            w
                        ));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha512-base64" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha512::crack(w);
            for h in hashes {
                if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                    let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                    if hex == hash {
                        bar.println(format!(
                            "{} hash decoded and cracked {} -> {} -> {}",
                            star.green(),
                            h,
                            hex,
                            w
                        ));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-256-base64" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha3_256::crack(w);
            for h in hashes {
                if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                    let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                    if hex == hash {
                        bar.println(format!(
                            "{} hash decoded and cracked {} -> {} -> {}",
                            star.green(),
                            h,
                            hex,
                            w
                        ));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    if hash_type == "sha3-512-base64" {
        parallel_crack(wordlist, rule, &bar, |w| {
            let hash = hashes::sha3_512::crack(w);
            for h in hashes {
                if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                    let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                    if hex == hash {
                        bar.println(format!(
                            "{} hash decoded and cracked {} -> {} -> {}",
                            star.green(),
                            h,
                            hex,
                            w
                        ));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        bar.finish();
        return found.load(Ordering::Relaxed);
    }

    // .par_bridge, iterates in paralel, for_each (each line, it's a word)
    wordlist.lines().par_bridge().for_each(|word| {
        bar.inc(1);

        // if rules enabled, generate variants; otherwise just the original word
        let words_to_try = if rule {
            crate::rules::apply(word)
        } else {
            vec![word.to_string()]
        };

        for w in &words_to_try {
            match hash_type {
                "md5" => {
                    let hash = hashes::md5::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                "md5-base64" => {
                    let hash = hashes::md5::crack(w);
                    for h in hashes {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                            let hex: String =
                                decoded.iter().map(|n| format!("{:02x}", n)).collect();
                            if hex == hash {
                                bar.println(format!(
                                    "{} hash decoded and cracked {} -> {} -> {}",
                                    star.green(),
                                    h,
                                    hex,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha1-base64" => {
                    let hash = hashes::sha1_hash::crack(w);
                    for h in hashes {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                            let hex: String =
                                decoded.iter().map(|m| format!("{:02x}", m)).collect();
                            if hex == hash {
                                bar.println(format!(
                                    "{} hash decoded and cracked {} -> {} -> {}",
                                    star.green(),
                                    h,
                                    hex,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha256" => {
                    let hash = hashes::sha256::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                "sha256-base64" => {
                    let hash = hashes::sha256::crack(w);
                    for h in hashes {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                            let hex: String =
                                decoded.iter().map(|m| format!("{:02x}", m)).collect();
                            if hex == hash {
                                bar.println(format!(
                                    "{} hash decoded and cracked {} -> {} -> {}",
                                    star.green(),
                                    h,
                                    hex,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha512" => {
                    let hash = hashes::sha512::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                "sha512-base64" => {
                    let hash = hashes::sha512::crack(w);
                    for h in hashes {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                            let hex: String =
                                decoded.iter().map(|m| format!("{:02x}", m)).collect();
                            if hex == hash {
                                bar.println(format!(
                                    "{} hash decoded and cracked {} -> {} -> {}",
                                    star.green(),
                                    h,
                                    hex,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha3-256" => {
                    let hash = hashes::sha3_256::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                "sha3-512" => {
                    let hash = hashes::sha3_512::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                "sha3-256-base64" => {
                    let hash = hashes::sha3_256::crack(w);
                    for h in hashes {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                            let hex: String =
                                decoded.iter().map(|m| format!("{:02x}", m)).collect();
                            if hex == hash {
                                bar.println(format!(
                                    "{} hash decoded and cracked {} -> {} -> {}",
                                    star.green(),
                                    h,
                                    hex,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha256/sha3-256" => {
                    let hash = hashes::sha256::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let hash = hashes::sha3_256::crack(w);
                        if hashes.contains(&hash.as_str()) {
                            bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                "sha512/sha3-512" => {
                    let hash = hashes::sha512::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let hash = hashes::sha3_512::crack(w);
                        if hashes.contains(&hash.as_str()) {
                            bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                "md5-salt" => {
                    for h in hashes {
                        if let Some((salt, target)) = h.split_once(':') {
                            let hash = hashes::md5::crack_with_salt(w, salt);
                            if hash == target {
                                bar.println(format!(
                                    "{} hash cracked [salt:{}] {} -> {}",
                                    star.green(),
                                    salt,
                                    target,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha1-salt" => {
                    for h in hashes {
                        if let Some((salt, target)) = h.split_once(':') {
                            let hash = hashes::sha1_hash::crack_with_salt(w, salt);
                            if hash == target {
                                bar.println(format!(
                                    "{} hash cracked [salt:{}] {} -> {}",
                                    star.green(),
                                    salt,
                                    target,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha256-salt" => {
                    for h in hashes {
                        if let Some((salt, target)) = h.split_once(':') {
                            let hash = hashes::sha256::crack_with_salt(w, salt);
                            if hash == target {
                                bar.println(format!(
                                    "{} hash cracked [salt:{}] {} -> {}",
                                    star.green(),
                                    salt,
                                    target,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha512-salt" => {
                    for h in hashes {
                        if let Some((salt, target)) = h.split_once(':') {
                            let hash = hashes::sha512::crack_with_salt(w, salt);
                            if hash == target {
                                bar.println(format!(
                                    "{} hash cracked [salt:{}] {} -> {}",
                                    star.green(),
                                    salt,
                                    target,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha3-256-salt" => {
                    for h in hashes {
                        if let Some((salt, target)) = h.split_once(':') {
                            let hash = hashes::sha3_256::crack_with_salt(w, salt);
                            if hash == target {
                                bar.println(format!(
                                    "{} hash cracked [salt:{}] {} -> {}",
                                    star.green(),
                                    salt,
                                    target,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha3-512-base64" => {
                    let hash = hashes::sha3_512::crack(w);
                    for h in hashes {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                            let hex: String =
                                decoded.iter().map(|m| format!("{:02x}", m)).collect();

                            if hex == hash {
                                bar.println(format!(
                                    "{} hash decoded and cracked {} -> {} -> {}",
                                    star.green(),
                                    h,
                                    hex,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "sha3-512-salt" => {
                    for h in hashes {
                        if let Some((salt, target)) = h.split_once(':') {
                            let hash = hashes::sha3_512::crack_with_salt(w, salt);
                            if hash == target {
                                bar.println(format!(
                                    "{} hash cracked [salt:{}] {} -> {}",
                                    star.green(),
                                    salt,
                                    target,
                                    w
                                ));
                                found.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                "bcrypt" => {
                    for h in hashes {
                        if hashes::bcrypt::crack(w, h) {
                            bar.println(format!("{} hash cracked {} -> {}", star.green(), h, w));
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                "ntlm" => {
                    let hash = hashes::ntlm::crack(w);
                    if hashes.contains(&hash.as_str()) {
                        bar.println(format!("{} hash cracked {} -> {}", star.green(), hash, w));
                        found.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {
                    bar.println(format!("\n{} unsupported type of hash", "[!]".red()));
                    return;
                }
            }
        }
    });

    bar.finish();

    found.load(Ordering::Relaxed)
}

fn parallel_crack<F>(wordlist: &str, rule: bool, bar: &ProgressBar, matcher: F)
where
    F: Fn(&str) + Sync + Send,
{
    wordlist.lines().par_bridge().for_each(|word| {
        bar.inc(1);

        if rule {
            for w in crate::rules::apply(word) {
                matcher(&w);
            }
        } else {
            matcher(word);
        }
    });
}
