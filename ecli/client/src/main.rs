use clap::{Parser, Subcommand};

mod utils;

use lib::{
    error::*,
    init_log,
    oci::{
        auth::{login, logout},
        pull, push,
    },
    runner::{client_action, run},
    ClientCmd, Signals, SIGINT,
};
use std::process;
use std::thread;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

/// ecli subcommands, including run, push, pull, login, logout.
#[derive(Subcommand)]
pub enum Action {
    Run {
        /// run without cache
        #[arg(long, short = 'n', default_value_t = false)]
        no_cache: bool,
        /// json output format
        #[arg(long, short = 'j', default_value_t = false)]
        json: bool,
        /// program path or url
        #[arg(allow_hyphen_values = true)]
        prog: Vec<String>,
    },

    #[clap(name = "client", about = "Client operations")]
    Client(ClientCmd),

    /// push wasm or oci image to registry
    Push {
        #[arg(long, short, default_value_t = ("app.wasm").to_string())]
        module: String,
        #[arg()]
        image: String,
    },

    /// pull oci image from registry
    Pull {
        /// wasm module url
        #[arg(short, long, default_value_t = ("app.wasm").to_string())]
        output: String,
        /// oci image url
        #[arg()]
        image: String,
    },

    /// login to oci registry
    Login {
        #[arg()]
        url: String,
    },

    /// logout from registry
    Logout {
        #[arg()]
        url: String,
    },
}

#[tokio::main]
async fn main() -> EcliResult<()> {
    let signals = Signals::new(&[SIGINT]);
    thread::spawn(move || match signals {
        Ok(mut signals_info) => {
            for sig in signals_info.forever() {
                println!("Received signal {:?}", sig);
                process::exit(0);
            }
            println!("Got signals info: {:?}", signals_info);
        }
        Err(error) => {
            eprintln!("Error getting signals info: {}", error);
        }
    });
    init_log();
    let args = Args::parse();
    match args.action {
        Action::Run { .. } => run(args.action.try_into()?).await,
        Action::Push { .. } => push(args.action.try_into()?).await,
        Action::Pull { .. } => pull(args.action.try_into()?).await,
        Action::Login { url } => login(url).await,
        Action::Logout { url } => logout(url),
        Action::Client(..) => client_action(args.action.try_into()?).await,
    }
}
