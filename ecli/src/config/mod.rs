//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::{
    error::{EcliError, EcliResult},
    runner::RunArgs,
    tar_reader::unpack_tar,
};
/// Re-export export format type from bpf-loader-lib
pub use bpf_loader_lib::export_event::ExportFormatType;

/// The ProgramType
pub enum ExportFormatType {
    ExportJson,
    ExportPlantText,
}

#[derive(Clone, Debug)]
pub enum ProgramType {
    /// Unknown
    Undefine,
    /// JSON-described bpf program
    JsonEunomia,
    /// A Wasm module which can be used for wasm-bpf
    WasmModule,
    /// A tar archive
    Tar,
}

impl TryFrom<&str> for ProgramType {
    type Error = EcliError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        match "" {
            _ if path.ends_with(".json") => Ok(ProgramType::JsonEunomia),
            _ if path.ends_with(".wasm") => Ok(ProgramType::WasmModule),
            _ if path.ends_with(".tar") => Ok(ProgramType::Tar),
            _ => Err(EcliError::UnknownSuffix(format!(
                "{} suffix incorrect, must end with .json, .wasm or .tar",
                path
            ))),
        }
    }
}
/// Definition of a ebpf container or program to run
pub struct ProgramConfigData {
    /// The program source, URL or local files
    pub url: String,
    /// Whether to use cache
    pub use_cache: bool,
    /// The btf archive path
    pub btf_path: Option<String>,
    /// program data buffer: wasm module or json
    pub program_data_buf: Vec<u8>,
    /// Extra args to the program
    pub extra_arg: Vec<String>,
    /// Type of the program
    pub prog_type: ProgramType,
    /// Export data type for the program
    pub export_format_type: ExportFormatType,
}

impl ProgramConfigData {
    /// Load a program configuration
    pub async fn async_try_from(args: &mut RunArgs) -> EcliResult<Self> {
        let _prog_buf = args.get_file_content().await?;
        let (prog_buf, btf_dir_path) = match args.prog_type {
            ProgramType::Tar => unpack_tar(args.get_file_content().await?.as_slice()),
            _ => (args.get_file_content().await?, None),
        };
        Ok(Self {
            url: args.file,
            use_cache: !args.no_cache,
            program_data_buf: prog_buf,
            extra_arg: args.extra_arg,
            btf_path: btf_dir_path,
            prog_type: args.prog_type,
            export_format_type: if args.export_to_json {
                ExportFormatType::Json
            } else {
                ExportFormatType::PlainText
            },
        })
    }
}
