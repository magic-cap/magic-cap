use magic_cap::ImmutableReadCap;
use magic_cap_cli::{
    main_anthology_create, main_anthology_list, main_debug_info, main_debug_locator, main_decrypt,
    main_encrypt, main_publish, main_reduce, main_verify,
};
use tracing_subscriber::FmtSubscriber;

// b'\xbd\xe1\xb4\x19\xc1+\xa9\xe8\xd9h\xc6u\xe5\xea\x01'
// ^ encrypted "attack at dawn!" with key all zeros, IV all zeros
// using tahoe libs.
use std::path::PathBuf;
use url::Url;

use clap::{Args, Parser, Subcommand};
use tracing::{Level, debug, error};

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
    // todo: maybe promote --catalog up here?
    // ("mcap reduce" doesn't use it, and not all "mcap debug" commands will, ...)
    // maybe clap gives us a way to say "--catalog is illegal for ..."?
}

#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum DebugCommands {
    #[command(about = "Convert given Read Cap (or Verify Cap) to a Location-Id")]
    Locator { capstr: String },

    #[command(about = "Print human-readable information about the Read Cap")]
    Info {
        #[arg(long)]
        catalog: Option<PathBuf>,

        capstr: String,
    },
}

#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum AnthologyCommands {
    #[command(about = "Create a new Anthology into a (possibly existing) Catalog")]
    Create { directory: PathBuf },

    #[command(about = "List the contents of an Anthology")]
    List { capstr: String },
    // talked about having a "anthology download" or similar that will
    // take an anthology and download it locally -- but probably wants
    // more thinking? Like maybe this is a good idea for anything or
    // any collection of Read Caps you have?
    //#[command(about = "")]
    //Download {
    //    directory: PathBuf,
    //},
}

#[derive(Subcommand)]
#[command(arg_required_else_help(true))]
enum Commands {
    #[command(about = "turn plaintext into a Read Cap + ciphertext")]
    Encrypt {
        // non-optional source of data
        plaintext: PathBuf,

        #[command(flatten)]
        ciphertext_store: CiphertextStore,

        #[arg(short, long, default_value_t = 4096)]
        blocksize: usize, // not Option because we have a default value
    },

    #[command(about = "turn a Read Cap + ciphertext into plaintext")]
    Decrypt {
        // this flatten is VERY IMPORTANT and took me days to discover.
        #[command(flatten)]
        ciphertext_loader: CiphertextLoad,

        // non-optional magic-cap string
        cap: ImmutableReadCap,

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

    #[command(about = "Tools to create and manipulate Anthologies")]
    Anthology {
        #[command(subcommand)]
        command: Option<AnthologyCommands>,
    },
}

/// When decrypting ciphertext, where is that ciphertext?
/// Catalog or File?
#[derive(Args, Clone)]
#[group(required = true, multiple = true)]
struct CiphertextLoad {
    #[arg(
        long,
        value_name("PATH"),
        env("MCAP_CATALOG"),
        help("root directory of a ciphertext catalog")
    )]
    local_catalog: Option<PathBuf>,

    #[arg(
        long,
        value_name("URL"),
        env("MCAP_URL"),
        help("root URL of a ciphertext catalog")
    )]
    url_catalog: Option<Url>,

    #[arg(
        short,
        long,
        value_name("FNAME"),
        help("path to a .mcap ciphertext file")
    )]
    local_file: Option<PathBuf>,

    #[arg(short, long, value_name("URL"), help("url of the ciphertext file"))]
    url_file: Option<Url>,
}

/// When encrypting, where does the output go?
/// Catalog, File, or both?
#[derive(Args, Clone, Debug)]
#[group(multiple = true)]
struct CiphertextStore {
    // index in a catalog
    #[arg(long)]
    catalog: Option<PathBuf>,
    // write to a local file
    #[arg(short, long)]
    output_file: Option<PathBuf>,
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
            ciphertext_store,
            blocksize,
        }) => main_encrypt(
            &mut std::io::stdout(),
            plaintext,
            &ciphertext_store.output_file,
            &ciphertext_store.catalog,
            *blocksize,
        ),
        Some(Commands::Decrypt {
            cap,
            ciphertext_loader: ciphertext_load,
            plaintext,
        }) => {
            let cl = ciphertext_load;
            main_decrypt(
                cap,
                &cl.local_catalog,
                &cl.url_catalog,
                &cl.local_file,
                &cl.url_file,
                plaintext,
            )
        }
        Some(Commands::Verify { cap, ciphertext }) => main_verify(cap, ciphertext),
        Some(Commands::Reduce { cap }) => main_reduce(&mut std::io::stdout(), cap),
        Some(Commands::Publish { catalog, output }) => {
            main_publish(&mut std::io::stdout(), catalog, output)
        }
        // todo: might make sense to promote --catalog to top-level
        Some(Commands::Debug { command }) => match command {
            Some(DebugCommands::Locator { capstr }) => main_debug_locator(capstr),
            Some(DebugCommands::Info { capstr, catalog }) => main_debug_info(capstr, catalog),
            None => Ok(()),
        },
        Some(Commands::Anthology { command }) => match command {
            Some(AnthologyCommands::Create { directory }) => main_anthology_create(directory),
            Some(AnthologyCommands::List { capstr }) => main_anthology_list(capstr),
            None => Ok(()),
        },
        None => Ok(()),
    };
    if let Err(e) = result {
        error!("Error: {}", e);
        std::process::exit(2);
    }
}
