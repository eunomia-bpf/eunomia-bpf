//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod bpf_compiler;
mod config;
mod document_parser;
mod export_types;
mod helper;
mod wasm;

#[cfg(test)]
pub(crate) mod tests;

use anyhow::Result;
use bpf_compiler::*;
use clap::Parser;
use config::{CompileArgs, EunomiaWorkspace};

fn main() -> Result<()> {
    use anyhow::anyhow;
    clang_sys::load()
        .map_err(|e| anyhow!("Failed to load libclang dynamically at runtime: {}", e))?;
    let args = CompileArgs::parse();
    flexi_logger::Logger::try_with_env_or_str(if args.verbose { "debug" } else { "info" })?
        .start()?;
    let workspace = EunomiaWorkspace::init(args)?;

    compile_bpf(&workspace.options)?;

    Ok(())
}
