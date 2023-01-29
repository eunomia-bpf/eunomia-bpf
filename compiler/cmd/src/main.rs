mod compile_bpf;
mod config;
mod document_parser;
mod export_types;

use anyhow::Result;
use clap::Parser;
use compile_bpf::*;
use config::{CompileOptions, EunomiaWorkspace};

fn main() -> Result<()> {
    let args = CompileOptions::parse();
    let workspace = EunomiaWorkspace::init(args)?;

    compile_bpf(&workspace.options)?;

    Ok(())
}
