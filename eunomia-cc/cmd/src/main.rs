mod compile_bpf;
mod config;
mod export_types;
use clap::Parser;
use compile_bpf::compile_bpf;
use config::Args;
use anyhow::Result;

fn main() -> Result<()> {
    let args = Args::parse();
    compile_bpf(&args)
}
