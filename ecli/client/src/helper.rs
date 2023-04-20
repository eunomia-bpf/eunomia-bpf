//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use ecli_lib::{
    config::ProgramType,
    error::{Error, Result},
    runner::helper::try_load_program_buf_and_guess_type,
};
use tokio::io::AsyncReadExt;
#[allow(unused)]
pub async fn load_prog_buf_and_guess_type(
    path: &str,
    user_prog_type: Option<ProgramType>,
) -> Result<(Vec<u8>, ProgramType)> {
    if path == "-" {
        let buf = read_stdio_input().await?;
        if let Some(v) = user_prog_type {
            Ok((buf, v))
        } else {
            Err(Error::InvalidParam(
                "You must manually specify the -p argument when reading program from stdio"
                    .to_string(),
            ))
        }
    } else {
        let (buf, prog_type) = try_load_program_buf_and_guess_type(path).await?;
        let prog_type = prog_type.or(user_prog_type).ok_or_else(|| {
            Error::InvalidParam(
                "Failed to guess the program type, please specify it through -p argument"
                    .to_string(),
            )
        })?;
        Ok((buf, prog_type))
    }
}
#[allow(unused)]
pub fn prog_type_value_parser(s: &str) -> std::result::Result<ProgramType, String> {
    Ok(match s.to_lowercase().as_str() {
        "json" | "jsoneunomia" => ProgramType::JsonEunomia,
        "tar" => ProgramType::Tar,
        "wasm" | "wasmmodule" => ProgramType::WasmModule,
        s => {
            return Err(format!(
                "Unknown program type: {s}. Valids are `json`, `tar`, and `wasm`"
            ))
        }
    })
}
#[allow(unused)]
pub async fn read_stdio_input() -> Result<Vec<u8>> {
    let mut result = vec![];
    tokio::io::stdin()
        .read_to_end(&mut result)
        .await
        .map_err(Error::IOErr)?;
    Ok(result)
}
