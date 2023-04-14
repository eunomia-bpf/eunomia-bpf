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

pub enum ExportFormatType {
    ExportJson,
    ExportPlantText,
}

pub enum ProgramType {
    Undefine,
    JsonEunomia,
    WasmModule,
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

pub struct ProgramConfigData {
    pub url: String,
    pub use_cache: bool,
    pub btf_path: Option<String>,
    //program data buffer: wasm module or json
    pub program_data_buf: Vec<u8>,
    pub extra_arg: Vec<String>,
    pub prog_type: ProgramType,
    pub export_format_type: ExportFormatType,
}

impl ProgramConfigData {
    pub async fn async_try_from(args: &mut RunArgs) -> EcliResult<Self> {
        let _prog_buf = args.get_file_content().await?;
        let (prog_buf, btf_dir_path) = match args.prog_type {
            ProgramType::Tar => unpack_tar(args.get_file_content().await?.as_slice()),
            _ => (args.get_file_content().await?, None),
        };
        Ok(Self {
            url: args.file.clone(),
            use_cache: !args.no_cache,
            program_data_buf: prog_buf,
            extra_arg: args.extra_arg.clone(),
            btf_path: btf_dir_path,
            prog_type: ProgramType::Undefine,
            export_format_type: if args.export_to_json {
                ExportFormatType::ExportJson
            } else {
                ExportFormatType::ExportPlantText
            },
        })
    }
}
