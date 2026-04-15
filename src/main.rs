mod backend;
mod benchmark;
mod cpu_backend;
mod cracker;
mod detector;
#[cfg(feature = "gpu")]
mod gpu_backend;
mod hashes;
mod rules;

use crate::backend::CrackingBackend;
use crate::cpu_backend::CpuBackend;
use clap::Parser;
use colored::Colorize;
use std::fs;

#[derive(Parser)] // sabe leer argumentos (derive(parser))
#[command(name = "brutecraber", version = "0.8.1")]
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

    #[arg(
        short = 't',
        default_value = "auto",
        help = "Hash type: md5, md5-base64, md5-salt, sha1, sha1-base64, sha1-salt, sha256, sha256-base64, sha256-salt, sha512, sha512-base64, sha512-salt, sha3-256, sha3-256-base64, sha3-256-salt, sha3-512, sha3-512-base64, sha3-512-salt, bcrypt, ntlm, argon2, scrypt, pbkdf2"
    )]
    hash: String,

    #[arg(short = 'r', long = "rules", default_value_t = false)]
    rules: bool,

    #[arg(long = "benchmark", default_value_t = false)]
    benchmark: bool,

    #[arg(long = "cpu", default_value_t = false, help = "Force CPU backend")]
    cpu: bool,
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
    println!("                                                v0.8.1");
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
        " {} MD5 · SHA1 · SHA256 · SHA512 · SHA3-256 · SHA3-512 · Bcrypt · NTLM · Argon2 · PBKDF2  {} hex · base64 · salted",
        "Supported:".truecolor(222, 74, 31),
        "Modes:".truecolor(222, 74, 31)
    );
    println!();
}

fn main() -> anyhow::Result<()> {
    banner();

    let star = "[*]";

    let args = Args::parse();

    if args.benchmark {
        let use_gpu = cfg!(feature = "gpu");
        benchmark::run(use_gpu);
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
            star.green(),
            auto_detect.yellow()
        );
    } else {
        println!("{} Selected hash: {}\n", star, auto_detect.green());
    }

    let force_cpu = args.cpu;

    let found = {
        #[cfg(feature = "gpu")]
        {
            use crate::gpu_backend::{self, GpuBackend};

            if force_cpu {
                println!("{} --cpu flag set, using CPU\n", "[*]".yellow());
                CpuBackend.run(&hashes, &wordlist, &auto_detect, args.rules)
            } else if !gpu_backend::supports(&auto_detect) {
                println!(
                    "{} hash {} not supported on GPU, using CPU\n",
                    "[*]".yellow(),
                    auto_detect
                );
                CpuBackend.run(&hashes, &wordlist, &auto_detect, args.rules)
            } else {
                match GpuBackend::new() {
                    Ok(gpu) => {
                        gpu.print_device_info();
                        gpu.run(&hashes, &wordlist, &auto_detect, args.rules)
                    }
                    Err(e) => {
                        println!(
                            "{} GPU unavailable ({}), falling back to CPU\n",
                            "[!]".yellow(),
                            e
                        );
                        CpuBackend.run(&hashes, &wordlist, &auto_detect, args.rules)
                    }
                }
            }
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = force_cpu;
            CpuBackend.run(&hashes, &wordlist, &auto_detect, args.rules)
        }
    };

    println!();

    if found == 0 {
        println!("{} failed cracking hashes or bad file\n", star.red());
    } else {
        println!("{} cracked {}/{} hashes", star.green(), found, hashes.len());
    }

    Ok(())
}
