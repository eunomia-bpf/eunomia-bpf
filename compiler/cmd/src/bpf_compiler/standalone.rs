//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::process::Command;

use crate::{config::Options, handle_std_command_with_log, helper::get_eunomia_data_dir};
use anyhow::{anyhow, bail, Context, Result};
use log::info;
use std::path::Path;

fn num_to_hex(v: u8) -> char {
    match v {
        0..=9 => (48 + v) as char,
        10..=15 => (v - 10 + 97) as char,
        _ => panic!(),
    }
}

pub(crate) fn render_standalone_source(opts: &Options) -> Result<String> {
    let template_source = include_str!("standalone_bpf_loader.template.c");

    let package_content = std::fs::read_to_string(opts.get_output_package_config_path())
        .with_context(|| anyhow!("Failed to read generated package artifact"))?;
    let bytes_str = package_content
        .as_bytes()
        .iter()
        .map(|x| {
            // For simplicity, we manually handle the conversion
            let a = x / 16;
            let b = x % 16;
            format!("\\x{}{}", num_to_hex(a), num_to_hex(b))
        })
        .collect::<Vec<_>>()
        .join("");
    Ok(template_source.replace("<REPLACE-HERE>", &bytes_str))
}

pub(crate) fn build_standalone_executable(
    opts: &Options,
    source_path: impl AsRef<Path>,
    executable_path: impl AsRef<Path>,
) -> Result<()> {
    info!("Generating standalone executable..");
    let libeunomia_path = get_eunomia_data_dir()?.join("libeunomia.a");
    if !libeunomia_path.exists() {
        bail!("`{:?}` does not exist, fetch one from https://github.com/eunomia-bpf/eunomia-bpf/actions",libeunomia_path);
    }

    let mut cmd = Command::new(&opts.compile_opts.parameters.clang_bin);
    cmd.arg("-Wall")
        .arg("-O2")
        .arg("-static")
        .arg(source_path.as_ref())
        .arg(libeunomia_path)
        .arg("-o")
        .arg(executable_path.as_ref());
    handle_std_command_with_log!(cmd, "Failed to build the standalone executable");

    Ok(())
}
