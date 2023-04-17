//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod config;
mod error;
mod json_runner;
mod oci;
mod runner;
mod tar_reader;
mod wasm_bpf_runner;
use clap::{Parser, Subcommand};
use env_logger::{Builder, Target};
use error::EcliResult;
use oci::{
    auth::{login, logout},
    pull, push,
};
use runner::run;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::{process, thread};

/// ecli subcommands, including run, push, pull, login, logout.
#[derive(Subcommand)]
pub enum Action {
    /// run ebpf program
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
    /// push wasm or oci image to registry
    Push {
        /// wasm module path
        #[arg(long, short, default_value_t = ("app.wasm").to_string())]
        module: String,
        /// oci image path
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
        /// oci login url
        #[arg()]
        url: String,
    },
    /// logout from registry
    Logout {
        /// oci logout url
        #[arg()]
        url: String,
    },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

fn init_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();
}

#[tokio::main]
async fn main() -> EcliResult<()> {
    let signals = Signals::new([SIGINT]);
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
    }
}
