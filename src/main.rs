mod cracker;
mod detector;
mod hashes;
mod rules;
mod benchmark;

use clap::Parser;
use colored::Colorize;
use std::fs;

#[derive(Parser)] // sabe leer argumentos (derive(parser))
#[command(name = "brutecraber", version = "0.7.1")]
struct Args {
    #[arg(
        short = 'f',
        help = "Path to file containing hashes",
        required_unless_present = "benchmark"
    )]
    file: Option<String>,

    #[arg(
        short = 'w',
        help = "Path to wordlist file",
        required_unless_present = "benchmark"
    )]
    wordlist: Option<String>,

    #[arg(short = 't', default_value = "auto", help = "Hash type...")]
    hash: String,

    #[arg(short = 'r', long = "rules", default_value_t = false)]
    rules: bool,

    #[arg(long = "benchmark", default_value_t = false)]
    benchmark: bool,
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
    println!("                                                v0.7.1");
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
        " {} MD5 · SHA1 · SHA256 · SHA512 · SHA3-256 · Bcrypt · NTLM  {} hex · base64 · salted",
        "Supported:".truecolor(222, 74, 31),
        "Modes:".truecolor(222, 74, 31)
    );
    println!();
}

fn main() -> anyhow::Result<()> {
    banner();

    let good_star = "[*]";
    let bad_star = "[*]";

    let args = Args::parse();

    if args.benchmark {
        benchmark::run();
        return Ok(());
    }

    let file = args
        .file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("[-] Missing -f (hash file)"))?;

    let wordlist_path = args
        .wordlist
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("[-] Missing -w (wordlist)"))?;

    let content = fs::read_to_string(file)?;
    let hashes: Vec<&str> = content.lines().collect();

    let bytes = fs::read(wordlist_path)?;
    let wordlist = String::from_utf8_lossy(&bytes).to_string();

    println!();
    println!("Selected file: {}", file.green());
    println!("Selected wordlist: {}", wordlist_path.green());
    println!();

    let auto_detect = if args.hash == "auto" {
        let detect_hash = hashes.first().unwrap_or(&"");
        detector::detect(detect_hash).to_string()
    } else {
        args.hash.clone()
    };

    if args.hash == "auto" {
        println!(
            "{} Auto detected hash: {}\n",
            good_star.green(),
            auto_detect.yellow()
        );
    } else {
        println!("Selected hash: {}\n", auto_detect.green());
    }

    let found = cracker::run(&hashes, &wordlist, &auto_detect, args.rules);

    println!();

    if found == 0 {
        println!("{} failed cracking hashes or bad file\n", bad_star.red());
    } else {
        println!(
            "{} cracked {}/{} hashes",
            good_star.green(),
            found,
            hashes.len()
        );
    }

    Ok(())
}