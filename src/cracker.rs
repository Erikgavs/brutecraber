use crate::hashes;
use base64::{Engine, engine::general_purpose};
use colored::Colorize;

pub fn run(hashes: &[&str], wordlist: &str, hash_type: &str) -> usize {
    let good_star = "[*]";
    let bad_star = "[*]";
    let mut found = 0;

    for word in wordlist.lines() {
        match hash_type {
            "md5" => {
                let hash = hashes::md5::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found += 1;
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
                            found += 1;
                        }
                    }
                }
            }
            "sha1" => {
                let hash = hashes::sha1_hash::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found += 1;
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
                            found += 1;
                        }
                    }
                }
            }
            "sha256" => {
                let hash = hashes::sha256::crack(word);
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found += 1;
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
                            found += 1;
                        }
                    }
                }
            }
            _ => {
                println!("\n{} unsupported type of hash", bad_star.red());
                break;
            }
        }
    }

    found
}
