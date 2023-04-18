//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use clap::{Parser, Subcommand};
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::{process, thread};

mod utils;

pub use clap::{Parser, Subcommand};
pub use env_logger::{Builder, Target};
pub use error::EcliResult;
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
pub use oci::{
    auth::{login, logout},
    pull, push,
};
use runner::run;
pub use runner::RemoteArgs;
use runner::{client_action, run, start_server};
pub use signal_hook::{consts::SIGINT, iterator::Signals};
use std::process;
use std::thread;
pub use std::{process, thread};

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
fn init_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();
}

#[derive(Parser)]
pub struct ClientCmd {
    #[clap(subcommand)]
    pub cmd: ClientSubCommand,

    #[clap(flatten)]
    pub opts: ClientOpts,
}

#[derive(Parser)]
pub enum ClientSubCommand {
    #[clap(name = "start", about = "start an ebpf programs on endpoint")]
    Start(StartCommand),

    #[clap(name = "stop", about = "stop running tasks on endpoint with id")]
    Stop(StopCommand),

    #[clap(name = "list", about = "list the ebpf programs running on endpoint")]
    List,
}

#[derive(Parser)]
pub struct ClientOpts {
    #[clap(short, long, help = "endpoint", default_value = "127.0.0.1")]
    pub endpoint: String,

    #[clap(short, long, help = "enpoint port", default_value = "8527")]
    pub port: u16,

    #[clap(short, long, help = "transport with https", default_value = "false")]
    pub secure: bool,
}

#[derive(Parser)]
pub struct StartCommand {
    #[clap(required = true)]
    pub prog: Vec<String>,
    #[clap(long)]
    pub extra_args: Option<Vec<String>>,
}

#[derive(Parser)]
pub struct StopCommand {
    #[clap(required = true)]
    pub id: Vec<i32>,
}

pub fn init_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();
}
use clap::{Parser, Subcommand};
mod utils;

use lib::{
    error::*,
    init_log,
    oci::{
        auth::{login, logout},
        pull, push,
    },
    process,
    runner::{client_action, run},
    ClientCmd, {Signals, SIGINT},
};
use std::thread;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
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
