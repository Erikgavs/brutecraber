use crate::hashes;
use base64::{Engine, engine::general_purpose};
use colored::Colorize;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn run(hashes: &[&str], wordlist: &str, hash_type: &str) -> usize {
    let good_star = "[*]";
    let bad_star = "[*]";
    // each thread waits to add a 1 (for example, in this case)
    let found = AtomicUsize::new(0);

    // .par_bridge, iterates in paralel, for_each (each line, it's a word)
    wordlist
        .lines()
        .par_bridge()
        .for_each(|word| match hash_type {
            "md5" => {
                let hash = hashes::md5::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
            "md5-base64" => {
                let hash = hashes::md5::crack(word);
                for h in hashes {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                        let hex: String = decoded.iter().map(|n| format!("{:02x}", n)).collect();
                        if hex == hash {
                            println!(
                                "{} hash decoded and cracked {} -> {} -> {}",
                                good_star.green(),
                                h,
                                hex,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "sha1" => {
                let hash = hashes::sha1_hash::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
            "sha1-base64" => {
                let hash = hashes::sha1_hash::crack(word);
                for h in hashes {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                        let hex: String = decoded.iter().map(|m| format!("{:02x}", m)).collect();
                        if hex == hash {
                            println!(
                                "{} hash decoded and cracked {} -> {} -> {}",
                                good_star.green(),
                                h,
                                hex,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "sha256" => {
                let hash = hashes::sha256::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
            "sha256-base64" => {
                let hash = hashes::sha256::crack(word);
                for h in hashes {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                        let hex: String = decoded.iter().map(|m| format!("{:02x}", m)).collect();
                        if hex == hash {
                            println!(
                                "{} hash decoded and cracked {} -> {} -> {}",
                                good_star.green(),
                                h,
                                hex,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "sha512" => {
                let hash = hashes::sha512::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found.fetch_add(1, Ordering::Relaxed);
                }
            }
            "sha512-base64" => {
                let hash = hashes::sha512::crack(word);
                for h in hashes {
                    if let Ok(decoded) = general_purpose::STANDARD.decode(h) {
                        let hex: String = decoded.iter().map(|m| format!("{:02x}", m)).collect();
                        if hex == hash {
                            println!(
                                "{} hash decoded and cracked {} -> {} -> {}",
                                good_star.green(),
                                h,
                                hex,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "md5-salt" => {
                for h in hashes {
                    if let Some((salt, target)) = h.split_once(':') {
                        let hash = hashes::md5::crack_with_salt(word, salt);
                        if hash == target {
                            println!(
                                "{} hash cracked [salt:{}] {} -> {}",
                                good_star.green(),
                                salt,
                                target,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "sha1-salt" => {
                for h in hashes {
                    if let Some((salt, target)) = h.split_once(':') {
                        let hash = hashes::sha1_hash::crack_with_salt(word, salt);
                        if hash == target {
                            println!(
                                "{} hash cracked [salt:{}] {} -> {}",
                                good_star.green(),
                                salt,
                                target,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "sha256-salt" => {
                for h in hashes {
                    if let Some((salt, target)) = h.split_once(':') {
                        let hash = hashes::sha256::crack_with_salt(word, salt);
                        if hash == target {
                            println!(
                                "{} hash cracked [salt:{}] {} -> {}",
                                good_star.green(),
                                salt,
                                target,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            "sha512-salt" => {
                for h in hashes {
                    if let Some((salt, target)) = h.split_once(':') {
                        let hash = hashes::sha512::crack_with_salt(word, salt);
                        if hash == target {
                            println!(
                                "{} hash cracked [salt:{}] {} -> {}",
                                good_star.green(),
                                salt,
                                target,
                                word
                            );
                            found.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            _ => {
                println!("\n{} unsupported type of hash", bad_star.red());
                return;
            }
        });

    found.load(Ordering::Relaxed)
}
