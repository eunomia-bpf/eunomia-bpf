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
    let args = CompileArgs::parse();
    flexi_logger::Logger::try_with_env_or_str(if args.verbose { "debug" } else { "info" })?
        .start()?;
    let workspace = EunomiaWorkspace::init(args)?;

    compile_bpf(&workspace.options)?;

    Ok(())
}

#[macro_export]
macro_rules! handle_runscript_output {
    ($code:expr, $command:expr, $output:expr, $error: expr, $error_msg: literal) => {
        if $code != 0 {
            log::info!("$ {}", $command);
            log::info!("{}", $output);
            log::error!("{}", $error);
            anyhow::bail!(concat!($error_msg, "(exit code = {})"), $code);
        }
    };
}
#[macro_export]
macro_rules! handle_runscript {
    ($command: expr, $error_msg: literal) => {{
        use anyhow::anyhow;
        use anyhow::Context;
        let (code, output, error) =
            run_script::run_script!($command).with_context(|| anyhow!($error_msg))?;
        $crate::handle_runscript_output!(code, $command, output, error, $error_msg);
        output
    }};
}

#[macro_export]
macro_rules! handle_runscrpt_with_log {
    ($command: expr, $error_msg: literal) => {{
        use log::debug;
        let output = $crate::handle_runscript!($command, $error_msg);
        debug!("$ {}", $command);
        debug!("{}", output);
        output
    }};
}
