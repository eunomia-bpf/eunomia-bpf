//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod config;
mod error;
mod wasm_bpf_runner;
mod json_runner;
mod oci;
mod runner;
use signal_hook::{consts::SIGINT, iterator::Signals};
use std::{thread, process};
use clap::{Parser, Subcommand};
use env_logger::{Builder, Target};
use error::EcliResult;
use oci::{
    auth::{login, logout},
    pull, push,
};
use runner::run;

#[derive(Subcommand)]
pub enum Action {
    Run {
        #[arg(long, short = 'n')]
        no_cache: Option<bool>,
        #[arg(long, short = 'j')]
        json: Option<bool>,
        #[arg(allow_hyphen_values = true)]
        prog: Vec<String>,
    },

    Push {
        #[arg(long, short, default_value_t = ("app.wasm").to_string())]
        module: String,
        #[arg()]
        image: String,
    },

    Pull {
        #[arg(short, long, default_value_t = ("app.wasm").to_string())]
        output: String,
        #[arg()]
        image: String,
    },

    Login {
        #[arg()]
        url: String,
    },

    Logout {
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
    let signals = Signals::new(&[SIGINT]);
    thread::spawn(move || {
        match signals {
            Ok(mut signals_info) => {
                for sig in signals_info.forever() {
                    println!("Received signal {:?}", sig);
                    process::exit(0);
                }
                println!("Got signals info: {:?}", signals_info);
            },
            Err(error) => {
                eprintln!("Error getting signals info: {}", error);
            }
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
