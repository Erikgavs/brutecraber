use anyhow;
use clap::Parser;
use colored::Colorize;
use md5::compute;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fs;

#[derive(Parser)] // sabe leer argumentos (derive(parser))
struct Args {
    #[arg(short = 'f')]
    file: String,

    #[arg(short = 'w')]
    wordlist: String,

    #[arg(short = 't')]
    hash: String,
}

fn banner() {
    println!(
        "{}",
        r" ___.                 __                            ___.".truecolor(222, 74, 31)
    );
    println!(
        "{}",
        r" \_ |_________ __ ___/  |_  ____   ________________ \_ |__   ___________"
            .truecolor(222, 74, 31)
    );
    println!(
        "{}",
        r"  | __ \_  __ \  |  \   __\/ __ \_/ ___\_  __ \__  \ | __ \_/ __ \_  __ \"
            .truecolor(222, 74, 31)
    );
    println!(
        "{}",
        r"  | \_\ \  | \/  |  /|  | \  ___/\  \___|  | \// __ \| \_\ \  ___/|  | \/"
            .truecolor(222, 74, 31)
    );
    println!(
        "{}",
        r"  |___  /__|  |____/ |__|  \___  >\___  >__|  (____  /___  /\___  >__|"
            .truecolor(222, 74, 31)
    );
    println!(
        "{}",
        r"      \/                       \/     \/           \/    \/     \/"
            .truecolor(222, 74, 31)
    );
    println!("                                                Author: erikgavs");
    println!("                                                v0.3.0");
    println!();
    println!(
        " [!] DISCLAIMER: This software is provided for ethical hacking and penetration testing"
    );
    println!(
        "     only. You are solely responsible for your actions. Using this tool against targets"
    );
    println!("     without prior consent is a violation of applicable laws. Use at your own risk.");
    println!();
}

fn main() -> anyhow::Result<()> {
    banner();
    let good_star = "[*]";
    let bad_star = "[*]";
    let mut found = 0;

    // we save user input (file and wordlist)
    let args = Args::parse(); // user input because Args (struct) have a string

    //read content
    let content = fs::read_to_string(&args.file)?;

    // each line is a str "sadsadads", "asdasdasda"
    let hashes: Vec<&str> = content.lines().collect();

    let wordlist = fs::read_to_string(&args.wordlist)?;

    println!();
    println!("Selected file: {}", args.file.green());
    println!("Selected wordlist: {}", args.wordlist.green());
    println!("Selected hash: {}", args.hash.green());
    println!();

    // for each word in wordlist, convert it to md5 hash
    // if the hash matches one in hashes.txt, that word is the original text
    for word in wordlist.lines() {
        match args.hash.as_str() {
            "md5" => {
                let hash = format!("{:x}", md5::compute(word));
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found += 1;
                }
            }
            "md5-base64" => {
                let hash = format!("{:x}", md5::compute(word));
                for h in &hashes {
                    if let Ok(decoded) = base64::decode(h) {
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
                let mut hash_engine = Sha1::new();
                hash_engine.update(word);
                let hash = format!("{:x}", hash_engine.finalize());
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);
                    found += 1;
                }
            }
            "sha1-base64" => {
                let mut hash_engine = Sha1::new();
                hash_engine.update(word);
                let hash = format!("{:x}", hash_engine.finalize());
                for h in &hashes {
                    if let Ok(decoded) = base64::decode(h) {
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
                let mut hash_engine = Sha256::new();
                hash_engine.update(word);
                let hash = format!("{:x}", hash_engine.finalize());
                if hashes.contains(&hash.as_str()) {
                    println!("{} hash cracked {} -> {}", good_star.green(), hash, word);

                    found += 1;
                }
            }
            _ => {
                println!("\n{} unsupported type of hash", bad_star.red());
                break;
            }
        }
    }

    println!();
    if found == 0 {
        println!("{} failed cracking hashes or bad file", bad_star.red());
    }

    if found > 0 {
        println!(
            "{} cracked {}/{} hashes",
            good_star.green(),
            found,
            hashes.len()
        );
    }
    Ok(())
}
