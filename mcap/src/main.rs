use mcap::{main_decrypt, main_encrypt, main_reduce, main_verify};

// b'\xbd\xe1\xb4\x19\xc1+\xa9\xe8\xd9h\xc6u\xe5\xea\x01'
// ^ encrypted "attack at dawn!" with key all zeros, IV all zeros
// using tahoe libs.
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version = "25.12.1")]
#[command(about = "
Magic Cap creation and reading

Work with Magic Cap strings and their associated metadata + ciphertext files
and/or plaintext.
")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum Commands {
    #[command(about = "turn plaintext into a Magic Cap + ciphertext")]
    Encrypt {
        #[arg(short, long)]
        plaintext: PathBuf,
        ciphertext: PathBuf,
    },

    #[command(about = "turn a Magic Cap + ciphertext into plaintext")]
    Decrypt {
        #[arg(long)]
        cap: String,

        #[arg(short, long)]
        ciphertext: PathBuf,
        #[arg(short, long)]
        plaintext: PathBuf,
        // #[arg(short, long)]
        // crypt_text: PathBuf,
    },

    #[command(about = "Confirm a ciphertext is valid")]
    Verify {
        #[arg(long)]
        cap: String,

        #[arg(short, long)]
        ciphertext: PathBuf,
    },

    #[command(about = "Make a less-powerful Cap (i.e. Read -> Verify)")]
    Reduce { cap: String },
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Encrypt {
            plaintext,
            ciphertext,
        }) => {
            main_encrypt(&mut std::io::stdout(), plaintext, ciphertext).unwrap();
        }
        Some(Commands::Decrypt {
            cap,
            ciphertext,
            plaintext,
        }) => {
            main_decrypt(&mut std::io::stdout(), cap, ciphertext, plaintext).unwrap();
        }
        Some(Commands::Verify { cap, ciphertext }) => {
            main_verify(cap, ciphertext).unwrap();
        }
        Some(Commands::Reduce { cap }) => {
            main_reduce(&mut std::io::stdout(), cap).unwrap();
        }
        None => {}
    }
}
