mod cracker;
mod hashes;

use anyhow;
use clap::Parser;
use colored::Colorize;
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
    println!("                                                v0.4.0");
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

    let found = cracker::run(&hashes, &wordlist, &args.hash);

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
