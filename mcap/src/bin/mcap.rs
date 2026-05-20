use magic_cap_cli::{
    main_debug_locator, main_decrypt, main_encrypt, main_publish, main_reduce, main_verify,
};
use tracing_subscriber::FmtSubscriber;

// b'\xbd\xe1\xb4\x19\xc1+\xa9\xe8\xd9h\xc6u\xe5\xea\x01'
// ^ encrypted "attack at dawn!" with key all zeros, IV all zeros
// using tahoe libs.
use std::path::PathBuf;
use url::Url;

use clap::{Parser, Subcommand};
use tracing::{Level, debug, error, info};

#[derive(Parser)]
#[command(version = "25.12.1")]
#[command(about = "
        ┏┳┓┏━┓┏━╸╻┏━╸        ┏━╸┏━┓┏━┓
O------ ┃┃┃┣━┫┃╺┓┃┃    ---   ┃  ┣━┫┣━┛ ------O
        ╹ ╹╹ ╹┗━┛╹┗━╸        ┗━╸╹ ╹╹

Create, read and verify Magic Cap strings and encrypted data.

Data is a file containing encrypted data and associated metadata.

A Read Cap is a string containing secret information to decrypt a corresponding Data.

A Verify Cap has only the power to confirm that the data is correct.
Any Read Cap may be turned into a Verify Cap offline.

Anyone with both the Data and corresponding Read Cap may re-create the plaintext.
")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// ERROR, WARN, INFO, DEBUG, TRACE in that order.
    #[arg(short, long, default_value_t = Level::INFO)]
    loglevel: Level,
}

#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum DebugCommands {
    #[command(about = "Convert given Read Cap (or Verify Cap) to a Location-Id")]
    Locator { capstr: String },
}

#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum Commands {
    #[command(about = "turn plaintext into a Read Cap + ciphertext")]
    Encrypt {
        // non-optional source of data
        plaintext: PathBuf,

        #[arg(short, long)]
        ciphertext: Option<PathBuf>,

        #[arg(long)]
        catalog: Option<PathBuf>,

        #[arg(short, long, default_value_t = 4096)]
        blocksize: usize, // not Option because we have a default value
    },

    #[command(about = "turn a Read Cap + ciphertext into plaintext")]
    Decrypt {
        // non-optional magic-cap string
        cap: String,

        // todo: shae says we can put these in a group .. see
        // https://stackoverflow.com/questions/76315540/how-do-i-require-one-of-the-two-clap-options/76315811#76315811
        #[arg(
            long,
            value_name("PATH"),
            env("MCAP_CATALOG"),
            help("root directory of a ciphertext catalog")
        )]
        catalog: Option<PathBuf>,

        #[arg(
            long,
            value_name("URL"),
            env("MCAP_URL"),
            help("root URL of a ciphertext catalog")
        )]
        catalog_url: Option<Url>,

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

    #[command(about = "Turn a Read Cap into a less-powerful Verify Cap")]
    Reduce { cap: String },

    #[command(
        about = "Turn a disc Catalog into one suitable for static hosting (as the REST API)."
    )]
    Publish {
        #[arg(help("local path of a Catalog"))]
        catalog: PathBuf,
        #[arg(help("output path for the REST-style static-hostable files"))]
        output: PathBuf,
    },

    #[command(
        about = "Debugging tools. Be careful copy-pasting any of these from untrusted sources"
    )]
    Debug {
        #[command(subcommand)]
        command: Option<DebugCommands>,
    },
}

fn main() {
    let cli = Cli::parse();
    // This will show TRACE, DEBUG, INFO, WARN and ERROR; see tokio's tracing examples
    let subscriber = FmtSubscriber::builder()
        .with_max_level(cli.loglevel)
        .with_writer(std::io::stderr)
        .finish();
    let _fail = tracing::subscriber::set_global_default(subscriber);
    debug!("after tracing subscriber init");
    debug!("set log level to {}", cli.loglevel);
    let result = match &cli.command {
        // if the MCAP output went to stdout a user will have a pretty
        // hard time separating the data file from the mcap string, so
        // we write the mcap string to stderr
        Some(Commands::Encrypt {
            plaintext,
            ciphertext,
            catalog,
            blocksize,
        }) => main_encrypt(
            &mut std::io::stderr(),
            plaintext,
            ciphertext,
            catalog,
            *blocksize,
        ),
        Some(Commands::Decrypt {
            cap,
            catalog,
            catalog_url,
            ciphertext,
            url,
            plaintext,
        }) => main_decrypt(
            &mut std::io::stdout(),
            cap,
            catalog,
            catalog_url,
            ciphertext,
            url,
            plaintext,
        ),
        Some(Commands::Verify { cap, ciphertext }) => main_verify(cap, ciphertext),
        Some(Commands::Reduce { cap }) => main_reduce(&mut std::io::stdout(), cap),
        Some(Commands::Publish { catalog, output }) => {
            main_publish(&mut std::io::stdout(), catalog, output)
        }
        Some(Commands::Debug { command }) => match command {
            Some(DebugCommands::Locator { capstr }) => main_debug_locator(capstr),
            None => Ok(()),
        },
        None => Ok(()),
    };
    if let Err(e) = result {
        error!("Error: {}", e);
        std::process::exit(2);
    }
}
