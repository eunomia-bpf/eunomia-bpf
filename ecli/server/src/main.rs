//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use clap::Parser;
mod utils;

use std::{process, thread};

use lib::{
    error::*,
    init_log,
    runner::start_server,
    {Signals, SIGINT},
};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[clap(short, long, help = "server port", default_value = "8527")]
    port: u16,
    #[arg(short, long, default_value = "127.0.0.1")]
    addr: String,
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
    start_server(args.into()).await
}
