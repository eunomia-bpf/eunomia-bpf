mod config;
mod error;
mod ewasm_runner;
mod json_runner;
mod runner;

use clap::{Parser, Subcommand};
use env_logger::{Builder, Target};
use error::EcliResult;
use runner::run;

#[derive(Subcommand)]
pub enum Action {
    Run {
        #[arg(long, short = 'n')]
        no_cache: Option<bool>,
        #[arg(long, short = 'j')]
        json: Option<bool>,
        #[arg(long, short = 'f')]
        file: String,
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

fn main() -> EcliResult<()> {
    init_log();
    let args = Args::parse();
    match args.action {
        Action::Run { .. } => run(args.action.into()),
    }
}
