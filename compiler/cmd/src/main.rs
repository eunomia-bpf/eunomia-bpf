mod compile_bpf;
mod config;
mod document_parser;
mod export_types;

use crate::config::create_eunomia_home;
use anyhow::Result;
use clap::Parser;
use compile_bpf::*;
use config::CompileOptions;

fn main() -> Result<()> {
    let args = CompileOptions::parse();
    create_eunomia_home()?;
    compile_bpf(&args)?;
    if !args.subskeleton {
        pack_object_in_config(&args)?;
    }
    Ok(())
}
