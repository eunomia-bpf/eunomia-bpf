//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{anyhow, Context, Result};
use clang::Clang;
use log::debug;
use std::env::var;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
/// Search the data directory of eunomia from environment variables
const EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";
static LIBCLANG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
pub fn get_eunomia_data_dir() -> Result<PathBuf> {
    if let Ok(e) = var(EUNOMIA_HOME_ENV) {
        return Ok(e.into());
    };

    // search from xdg standard directory
    let eunomia_home_search_path: Vec<PathBuf> = if let Ok(e) = var("XDG_DATA_HOME") {
        e.split(':')
            .map(|s| PathBuf::from(format!("{s}/eunomia")))
            .collect()
    } else {
        if let Ok(e) = var("HOME") {
            let home_dir = PathBuf::from(e);
            let eunomia_home = home_dir.join(".local/share/eunomia");

            if home_dir.exists() {
                if !eunomia_home.exists() {
                    std::fs::create_dir_all(&eunomia_home).with_context(|| {
                        anyhow!(
                            "Unable to create data directory for eunomia: {}",
                            eunomia_home.to_string_lossy()
                        )
                    })?;
                }
                return Ok(eunomia_home);
            }
        }
        Vec::new()
    };

    debug!("Checking if {:?} exist", &eunomia_home_search_path);

    return eunomia_home_search_path
        .into_iter()
        .find(|p| p.exists())
        .ok_or(anyhow!(
            "eunomia data home not found, try setting `EUNOMIA_HOME`"
        ));
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

pub fn with_clang<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Clang) -> Result<T>,
{
    let _guard = LIBCLANG_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clang_sys::load()
        .map_err(|e| anyhow!("Failed to load libclang dynamically at runtime: {}", e))?;
    let clang = Clang::new().map_err(|e| anyhow!("Failed to create Clang instance: {}", e))?;
    f(&clang)
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
