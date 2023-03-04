//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    vec,
};

use log::{debug, info};
use url::Url;

use crate::{
    config::{ProgramConfigData, ProgramType},
    error::{EcliError, EcliResult},
    json_runner::json::handle_json,
    oci::{default_schema_port, parse_img_url, wasm_pull},
    wasm_bpf_runner::wasm::handle_wasm,
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
    pub async fn get_file_content(&mut self) -> EcliResult<Vec<u8>> {
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

        // assume file is from oras
        if let Ok((_, _, _, repo_url)) = parse_img_url(self.file.as_str()) {
            info!("try read content from repo url: {}", repo_url);
            if let Ok(data) = wasm_pull(self.file.as_str()).await {
                self.prog_type = ProgramType::WasmModule;
                return Ok(data);
            };
            info!(
                "fail to read content from repo url: {}, try next type",
                repo_url
            );
        }

        // assume file is valid url
        let Ok(url) = Url::parse(&self.file) else {
            return Err(EcliError::UnknownFileType(format!("unknown type of {}, must file path or valid url", self.file)));
        };

        info!(
            "try read content from url: {}",
            format!(
                "{}://{}:{}{}?{}",
                url.scheme(),
                if let Some(host) = url.host() {
                    host.to_string()
                } else {
                    return Err(EcliError::UnknownFileType(format!(
                        "unknown type of {}, must file path or valid url",
                        self.file
                    )));
                },
                url.port().unwrap_or(default_schema_port(url.scheme())?),
                url.path(),
                url.query().unwrap_or_default()
            )
        );

        self.prog_type = ProgramType::try_from(url.path())?;

        content = reqwest::blocking::get(url.as_str())
            .map_err(|e| EcliError::HttpError(e.to_string()))?
            .bytes()
            .unwrap()
            .to_vec();

        Ok(content)
    }
}

impl TryFrom<Action> for RunArgs {
    type Error = EcliError;

    fn try_from(act: Action) -> Result<Self, Self::Error> {
        let Action::Run { no_cache, json, mut prog } = act else {
            unreachable!()
        };
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

pub async fn run(mut arg: RunArgs) -> EcliResult<()> {
    let conf = ProgramConfigData::async_try_from(&mut arg).await?;
    match arg.prog_type {
        ProgramType::JsonEunomia => handle_json(conf),
        ProgramType::WasmModule => handle_wasm(conf),
        _ => unreachable!(),
    }
}
