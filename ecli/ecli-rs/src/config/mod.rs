mod json;

use std::ffi::{c_char, CString};

use crate::{
    error::{EcliError, EcliResult},
    json_runner::new_json_config,
    runner::RunArgs,
};

use self::json::JsonProg;

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
    pub extra_arg: Vec<String>,
    pub prog_type: ProgramType,
    pub export_format_type: ExportFormatType,
}

impl ProgramConfigData {
    fn rewrite_prog_meta(&mut self) -> EcliResult<()> {
        let mut j: JsonProg = serde_json::from_slice(&self.program_data_buf)
            .map_err(|e| EcliError::JsonError(e.to_string()))?;
        let meta =
            serde_json::to_string(&j.meta).map_err(|e| EcliError::JsonError(e.to_string()))?;

        let meta_c_str = CString::new(meta).map_err(|e| EcliError::Other(e.to_string()))?;
        let mut extra_arg_raw = vec![];
        for i in self.extra_arg.iter() {
            let arg = CString::new(i.as_bytes()).unwrap();
            extra_arg_raw.push(arg.as_ptr() as *mut c_char)
        }

        unsafe {
            let new_conf = new_json_config(
                meta_c_str.as_ptr(),
                extra_arg_raw.as_mut_ptr(),
                (extra_arg_raw.len() as i32).into(),
            );
            if new_conf.is_null() {
                return Err(EcliError::BpfError(
                    "get new config with prog param fail".to_string(),
                ));
            }

            j.meta = serde_json::from_slice(CString::from_raw(new_conf).as_bytes())
                .map_err(|e| EcliError::JsonError(e.to_string()))?
        }

        self.program_data_buf = serde_json::to_string(&j).unwrap().as_bytes().to_vec();
        Ok(())
    }
}

impl TryFrom<&mut RunArgs> for ProgramConfigData {
    type Error = EcliError;

    fn try_from(args: &mut RunArgs) -> Result<Self, Self::Error> {
        let prog_buf = args.get_file_content()?;
        let mut s = Self {
            url: args.file.clone(),
            use_cache: !args.no_cache,
            program_data_buf: prog_buf,
            extra_arg: args.extra_arg.clone(),
            prog_type: ProgramType::Undefine,
            export_format_type: if args.export_to_json {
                ExportFormatType::ExportJson
            } else {
                ExportFormatType::ExportPlantText
            },
        };
        s.rewrite_prog_meta()?;
        Ok(s)
    }
}
