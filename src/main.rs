mod cracker;
mod detector;
mod hashes;
mod rules;

use anyhow;
use clap::Parser;
use colored::Colorize;
use std::fs;

#[derive(Parser)] // sabe leer argumentos (derive(parser))
#[command(name = "brutecraber", version = "0.5.0")]
struct Args {
    #[arg(short = 'f', help = "Path to file containing hashes")]
    file: String,

    #[arg(short = 'w', help = "Path to wordlist file")]
    wordlist: String,

    #[arg(
        short = 't',
        default_value = "auto",
        help = "Hash type: md5, md5-base64, md5-salt, sha1, sha1-base64, sha1-salt, sha256, sha256-base64, sha256-salt, sha512, sha512-base64, sha512-salt"
    )]
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
    println!("                                                v0.5.0");
    println!();
    println!(
        " [!] DISCLAIMER: This software is provided for ethical hacking and penetration testing"
    );
    println!(
        "     only. You are solely responsible for your actions. Using this tool against targets"
    );
    println!("     without prior consent is a violation of applicable laws. Use at your own risk.");
    println!();
    println!(
        " {} MD5 · SHA1 · SHA256 · SHA512  {} hex · base64 · salted",
        "Supported:".truecolor(222, 74, 31),
        "Modes:".truecolor(222, 74, 31)
    );
    println!();
}

fn main() -> anyhow::Result<()> {
    banner();
    let good_star = "[*]";
    let bad_star = "[*]";

    // we save user input (file and wordlist)
    let args = Args::parse(); // user input because Args (struct) have a string

    //read content
    let content = fs::read_to_string(&args.file)?;

    // each line is a str "sadsadads", "asdasdasda"
    let hashes: Vec<&str> = content.lines().collect();

    let bytes = fs::read(&args.wordlist)?;
    let wordlist = String::from_utf8_lossy(&bytes).to_string();

    println!();
    println!("Selected file: {}", args.file.green());
    println!("Selected wordlist: {}", args.wordlist.green());
    println!();

    let auto_detect = if args.hash == "auto" {
        // get's the first hash of the list
        // unwrap_or(&"") -> if the txt is empty, use a empty string
        let detect_hash = hashes.first().unwrap_or(&"");
        detector::detect(detect_hash).to_string()
    } else {
        args.hash.clone()
    };

    // hash print
    if args.hash == "auto" {
        println!(
            "{} Auto detected hash: {}\n",
            good_star.green(),
            auto_detect.yellow()
        );
    } else {
        println!("Selected hash: {}\n", auto_detect.green());
    }

    let found = cracker::run(&hashes, &wordlist, &auto_detect);

    println!();
    if found == 0 {
        println!("{} failed cracking hashes or bad file\n", bad_star.red());
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
