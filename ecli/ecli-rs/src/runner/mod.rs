use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    vec,
};

use log::{debug, info};
use url::Url;

use crate::{
    config::ProgramType,
    error::{EcliError, EcliResult},
    ewasm_runner::wasm::handle_wasm,
    json_runner::json::handle_json,
    Action,
};

pub struct RunArgs {
    pub no_cache: bool,
    pub export_to_json: bool,
    // file path or url
    pub file: String,
    pub extra_arg: Vec<String>,
    pub prog_type: ProgramType,
}

impl RunArgs {
    pub fn get_file_content(&mut self) -> EcliResult<Vec<u8>> {
        let mut content = vec![];

        if self.file == "-" {
            // read from stdin
            debug!("read content from stdin");
            io::stdin()
                .read_to_end(&mut content)
                .map_err(|e| EcliError::IOErr(e))?;
            self.prog_type = ProgramType::JsonEunomia;
            return Ok(content);
        }

        // assume file is valid file path
        let path = Path::new(self.file.as_str());
        if path.exists() && path.is_file() {
            self.prog_type = ProgramType::try_from(path.to_str().unwrap())?;

            // read from file
            info!("read content from file {}", self.file);
            let mut f = File::open(path).map_err(|e| EcliError::IOErr(e))?;
            f.read_to_end(&mut content)
                .map_err(|e| EcliError::IOErr(e))?;

            return Ok(content);
        }

        // assume file is valid url
        let Ok(url) = Url::parse(&self.file) else {
            return Err(EcliError::UnknownFileType(format!("unknown type of {}, must file path or valid url", self.file)));
        };
        self.prog_type = ProgramType::try_from(url.path())?;

        info!("read content from url {}", self.file);
        ureq::get(url.as_str())
            .call()
            .map_err(|e| EcliError::HttpError(e.to_string()))?
            .into_reader()
            .read_to_end(&mut content)
            .map_err(|e| EcliError::IOErr(e))?;
        Ok(content)
    }
}

impl TryFrom<Action> for RunArgs {
    type Error = EcliError;

    fn try_from(act: Action) -> Result<Self, Self::Error> {
        match act {
            Action::Run {
                no_cache,
                json,
                mut prog,
            } => {
                if prog.len() == 0 {
                    return Err(EcliError::ParamErr("prog not present".to_string()));
                }
                Ok(Self {
                    no_cache: no_cache.unwrap_or_default(),
                    export_to_json: json.unwrap_or_default(),
                    file: prog.remove(0),
                    extra_arg: prog,
                    prog_type: ProgramType::Undefine,
                })
            }
        }
    }
}

pub fn run(mut arg: RunArgs) -> EcliResult<()> {
    let conf = (&mut arg).try_into()?;
    match arg.prog_type {
        ProgramType::JsonEunomia => handle_json(conf),
        ProgramType::WasmModule => handle_wasm(conf),
        _ => unreachable!(),
    }
}
