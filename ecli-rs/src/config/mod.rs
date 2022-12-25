use crate::{error::EcliError, runner::RunArgs};

pub enum ExportFormatType {
    ExportJson,
    ExportPlantText,
}

pub enum ProgramType {
    Undefine,
    JsonEunomia,
    WasmModule,
}

impl TryFrom<&str> for ProgramType {
    type Error = EcliError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        match "" {
            _ if path.ends_with(".json") => Ok(ProgramType::JsonEunomia),
            _ if path.ends_with(".wasm") => Ok(ProgramType::WasmModule),
            _ => {
                return Err(EcliError::UnknownSuffix(format!(
                    "{} suffix incorrect, must end with .json or .wasm",
                    path
                )))
            }
        }
    }
}

pub struct ProgramConfigData {
    pub url: String,
    pub use_cache: bool,
    //program data buffer: wasm module or json
    pub program_data_buf: Vec<u8>,
    pub prog_type: ProgramType,
    pub export_format_type: ExportFormatType,
}

impl TryFrom<&mut RunArgs> for ProgramConfigData {
    type Error = EcliError;

    fn try_from(args: &mut RunArgs) -> Result<Self, Self::Error> {
        let prog_buf = args.get_file_content()?;
        Ok(Self {
            url: args.file.clone(),
            use_cache: !args.no_cache,
            program_data_buf: prog_buf,
            prog_type: ProgramType::Undefine,
            export_format_type: if args.export_to_json {
                ExportFormatType::ExportJson
            } else {
                ExportFormatType::ExportPlantText
            },
        })
    }
}
