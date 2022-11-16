#![allow(dead_code)]
mod bindings;
mod bpfmanager;
mod bpfprog;
mod config;
mod server;
mod state;

extern crate lazy_static;
extern crate link_cplusplus;
use clap::Parser;
use config::ExporterConfig;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Sets a custom config file
    #[clap(short, long, value_parser, default_value = "config.yaml")]
    config: String,
}

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Args::parse();

    let config = ExporterConfig::from_file(&cli.config)?;
    server::start_server(&config)?;
    Ok(())
}
