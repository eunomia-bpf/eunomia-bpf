//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::str::FromStr;

use crate::error::Error;
/// Re-export export format type from bpf-loader-lib

/// The ProgramType
#[derive(Clone, Debug, PartialEq)]
pub enum ProgramType {
    /// JSON-described bpf program
    JsonEunomia,
    /// A Wasm module which can be used for wasm-bpf
    WasmModule,
    /// A tar archive
    Tar,
}

impl TryFrom<&str> for ProgramType {
    type Error = Error;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        match path.split('.').last().unwrap() {
            "json" => Ok(ProgramType::JsonEunomia),
            "wasm" => Ok(ProgramType::WasmModule),
            "tar" => Ok(ProgramType::Tar),
            _ => Err(Error::UnknownSuffix(format!(
                "{} suffix incorrect, must end with .json, .wasm or .tar",
                path
            ))),
        }
    }
}

impl FromStr for ProgramType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "JsonEunomia" => Ok(ProgramType::JsonEunomia),
            "Tar" => Ok(ProgramType::Tar),
            "WasmModule" => Ok(ProgramType::WasmModule),
            &_ => Err(Error::Other("fail parse program type str".to_string())),
        }
    }
}
