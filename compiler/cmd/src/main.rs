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

use std::{path::PathBuf, str::FromStr};

use anyhow::Result;
use bpf_compiler::*;
use clap::Parser;
use config::{CompileArgs, EunomiaWorkspace};
use log::warn;
use walkdir::WalkDir;

fn main() -> Result<()> {
    use anyhow::anyhow;
    // Searches for the libclang in the appimage runner-defined paths, if applies
    if let Ok(v) = std::env::var("EUNOMIA_APPIMAGE_DEFINED_LD_LIBRARY_PATH") {
        let mut libclang_path = None;
        for dir in v.split(':') {
            let dir = PathBuf::from_str(dir)?;
            if dir.exists() {
                for entry in WalkDir::new(dir).into_iter() {
                    let entry = entry?;
                    if entry.file_type().is_file()
                        && entry.file_name().to_string_lossy().starts_with("libclang")
                    {
                        libclang_path =
                            Some(entry.path().parent().unwrap().to_string_lossy().to_string());
                    }
                }
            }
        }
        if let Some(v) = libclang_path {
            std::env::set_var("LIBCLANG_PATH", v);
        } else {
            warn!("libclang not found in EUNOMIA_APPIMAGE_DEFINED_LD_LIBRARY_PATH. Caution for library version issues.");
        }
    }
    clang_sys::load()
        .map_err(|e| anyhow!("Failed to load libclang dynamically at runtime: {}", e))?;

    let args = CompileArgs::parse();

    flexi_logger::Logger::try_with_env_or_str(if args.verbose { "debug" } else { "info" })?
        .start()?;
    let workspace = EunomiaWorkspace::init(args)?;

    compile_bpf(&workspace.options)?;

    Ok(())
}
