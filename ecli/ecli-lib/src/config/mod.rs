//!  SPDX-License-Identifier: MIT
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
        match s.to_ascii_lowercase().as_str() {
            "json" | "jsoneunomia" => Ok(ProgramType::JsonEunomia),
            "tar" => Ok(ProgramType::Tar),
            "wasm" | "wasmmodule" => Ok(ProgramType::WasmModule),
            _ => Err(Error::Other(format!(
                "fail parse program type str: {s}. valid values are json, tar, wasm"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::ProgramType;

    #[test]
    fn parse_program_type_aliases() {
        assert_eq!(
            ProgramType::from_str("json").unwrap(),
            ProgramType::JsonEunomia
        );
        assert_eq!(
            ProgramType::from_str("JsonEunomia").unwrap(),
            ProgramType::JsonEunomia
        );
        assert_eq!(
            ProgramType::from_str("wasm").unwrap(),
            ProgramType::WasmModule
        );
        assert_eq!(
            ProgramType::from_str("WasmModule").unwrap(),
            ProgramType::WasmModule
        );
        assert_eq!(ProgramType::from_str("tar").unwrap(), ProgramType::Tar);
        assert_eq!(ProgramType::from_str("Tar").unwrap(), ProgramType::Tar);
    }

    #[test]
    fn reject_unknown_program_type() {
        assert!(ProgramType::from_str("unknown").is_err());
    }
}
