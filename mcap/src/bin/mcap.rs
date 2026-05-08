use magic_cap_cli::{main_decrypt, main_encrypt, main_reduce, main_verify};

// b'\xbd\xe1\xb4\x19\xc1+\xa9\xe8\xd9h\xc6u\xe5\xea\x01'
// ^ encrypted "attack at dawn!" with key all zeros, IV all zeros
// using tahoe libs.
use std::path::PathBuf;
use url::Url;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version = "25.12.1")]
#[command(about = "
        ┏┳┓┏━┓┏━╸╻┏━╸        ┏━╸┏━┓┏━┓
O------ ┃┃┃┣━┫┃╺┓┃┃    ---   ┃  ┣━┫┣━┛ ------O
        ╹ ╹╹ ╹┗━┛╹┗━╸        ┗━╸╹ ╹╹

Create, read and verify Magic Cap strings and encrypted data.

Data is a file containing encrypted data and associated metadata.

A Read Cap is a string containing secret information to decrypt a corresponding Data.

A Verify Cap has the power to confirm that the data is correct.
Any Read Cap may be turned into a Verify Cap.

Anyone with both the Data and corresponding Read Cap may re-create the plaintext.
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
        // non-optional source of data
        plaintext: PathBuf,

        #[arg(short, long)]
        ciphertext: Option<PathBuf>,

        #[arg(long)]
        catalog: Option<PathBuf>,
    },

    #[command(about = "turn a Magic Cap + ciphertext into plaintext")]
    Decrypt {
        // non-optional magic-cap string
        cap: String,

        // todo: shae says we can put these in a group .. see
        // https://stackoverflow.com/questions/76315540/how-do-i-require-one-of-the-two-clap-options/76315811#76315811
        #[arg(
            long,
            value_name("PATH"),
            help("root directory of a ciphertext catalog")
        )]
        catalog: Option<PathBuf>,

        #[arg(
            short,
            long,
            value_name("FNAME"),
            help("path to a .mcap ciphertext file")
        )]
        ciphertext: Option<PathBuf>,

        #[arg(short, long, value_name("URL"), help("url of the ciphertext file"))]
        url: Option<Url>,

        #[arg(
            short,
            long,
            value_name("FNAME"),
            help("path to write plaintext to (default: stdout)")
        )]
        plaintext: Option<PathBuf>,
        // #[arg(short, long)]
        // crypt_text: PathBuf,
    },

    #[command(about = "Confirm a ciphertext is valid")]
    Verify {
        cap: String,

        #[arg(short, long)]
        ciphertext: PathBuf,
    },

    #[command(about = "Make a less-powerful Cap (i.e. Read -> Verify)")]
    Reduce { cap: String },
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Some(Commands::Encrypt {
            plaintext,
            ciphertext,
            catalog,
        }) => main_encrypt(&mut std::io::stdout(), plaintext, ciphertext, catalog),
        Some(Commands::Decrypt {
            cap,
            catalog,
            ciphertext,
            url,
            plaintext,
        }) => main_decrypt(
            &mut std::io::stdout(),
            cap,
            catalog,
            ciphertext,
            url,
            plaintext,
        ),
        Some(Commands::Verify { cap, ciphertext }) => main_verify(cap, ciphertext),
        Some(Commands::Reduce { cap }) => main_reduce(&mut std::io::stdout(), cap),
        None => Ok(()),
    };
    if let Err(e) = result {
        println!("Error: {}", e);
        std::process::exit(2);
    }
}
