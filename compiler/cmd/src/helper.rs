//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use log::debug;
/// Get the data directory of eunomia ($HOME/.eunomia)
pub fn get_eunomia_data_dir() -> Result<PathBuf> {
    let dir = home::home_dir()
        .ok_or_else(|| anyhow!("Unable to get home directory of the current user"))?
        .join(".eunomia");
    if !dir.exists() {
        std::fs::create_dir_all(&dir).with_context(|| {
            anyhow!(
                "Unable to create data directory for eunomia: {}",
                dir.to_string_lossy()
            )
        })?;
    }
    Ok(dir)
}

/// Get target arch: x86 or arm, etc
pub fn get_target_arch() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "powerpc64" => "powerpc",
        "mips64" => "mips",
        "riscv64" => "riscv",
        arch => arch,
    };

    debug!("Target architecture: {arch}");

    arch.to_string()
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

#[macro_export]
macro_rules! handle_std_command_with_log {
    ($cmd: expr, $error_msg: literal) => {{
        use anyhow::bail;
        let cmd_ref = &mut $cmd;
        let output = cmd_ref.output().with_context(|| anyhow!($error_msg))?;
        if !output.status.success() {
            log::info!("$ {:?} {:?}", cmd_ref.get_program(), cmd_ref.get_args());
            log::info!("{}", String::from_utf8_lossy(&output.stdout));
            log::error!("{}", String::from_utf8_lossy(&output.stderr));
            bail!(
                concat!($error_msg, "(exit code = {:?})"),
                output.status.code()
            );
        }
        log::debug!("$ {:?} {:?}", cmd_ref.get_program(), cmd_ref.get_args());
        log::debug!("{}", String::from_utf8_lossy(&output.stdout));
        String::from_utf8_lossy(&output.stdout).to_string()
    }};
}
