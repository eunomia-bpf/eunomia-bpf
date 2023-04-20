//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    vec,
};
pub mod models;
pub mod response;
use log::{debug, info};
use response::LogPostResponse;
use serde_json::json;
use tokio::time;
use url::Url;

pub use crate::ClientSubCommand;
use crate::{
    config::{ProgramConfigData, ProgramType},
    error::{EcliError, EcliResult},
    json_runner::handle_json,
    oci::{default_schema_port, parse_img_url, wasm_pull},
    runner::response::{ListGetResponse, StartPostResponse, StopPostResponse},
    wasm_bpf_runner::wasm::handle_wasm,
    Action,
};

/// Args accepted by the ecli when running the ebpf program
#[derive(Clone)]
pub struct RunArgs {
    /// whether to use cache
    pub no_cache: bool,
    /// json as output format
    pub export_to_json: bool,
    /// file path or url
    pub file: String,
    /// extra operating parameters
    pub extra_arg: Vec<String>,
    /// program type: wasm url json or tar
    pub prog_type: ProgramType,
}

pub mod server;
pub mod utils;

impl Default for RunArgs {
    fn default() -> Self {
        Self {
            no_cache: false,
            export_to_json: false,
            file: String::default(),
            extra_arg: Vec::new(),
            prog_type: ProgramType::Undefine,
        }
    }
}
impl RunArgs {
    /// parsing ebpf programs from path or url
    pub async fn get_file_content(&mut self) -> EcliResult<Vec<u8>> {
        let mut content = vec![];

        if self.file == "-" {
            // read from stdin
            debug!("read content from stdin");
            io::stdin()
                .read_to_end(&mut content)
                .map_err(EcliError::IOErr)?;
            self.prog_type = ProgramType::JsonEunomia;
            return Ok(content);
        }

        // assume file is valid file path
        let path = Path::new(self.file.as_str());
        if path.exists() && path.is_file() {
            self.prog_type = ProgramType::try_from(path.to_str().unwrap())?;

            // read from file
            info!("read content from file {}", self.file);
            let mut f = File::open(path).map_err(EcliError::IOErr)?;
            f.read_to_end(&mut content).map_err(EcliError::IOErr)?;

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
            .map_err(|e| EcliError::Other(e.to_string()))
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
        if prog.is_empty() {
            return Err(EcliError::ParamErr("prog not present".to_string()));
        }
        Ok(Self {
            no_cache,
            export_to_json: json,
            file: prog.remove(0),
            extra_arg: prog,
            prog_type: ProgramType::Undefine,
        })
    }
}

pub struct RemoteArgs {
    pub client: Option<ClientArgs>,
    pub server: Option<Action>,
}

#[derive(Default)]
pub struct ClientArgs {
    pub action_type: ClientActions,
    pub id: Vec<i32>,
    pub addr: String,
    pub port: u16,
    pub follow: bool,
    pub run_args: RunArgs,
}

pub enum ClientActions {
    Start,
    Stop,
    Log,
    Pause,
    Resume,
    List,
}

impl Default for ClientActions {
    fn default() -> Self {
        Self::List
    }
}

pub async fn run(arg: RunArgs) -> EcliResult<()> {
    let conf = ProgramConfigData::async_try_from(arg).await?;
    match conf.prog_type {
        ProgramType::JsonEunomia => handle_json(conf),
        ProgramType::Tar => handle_json(conf),
        ProgramType::WasmModule => handle_wasm(conf),
        _ => unreachable!(),
    }
}

pub struct Dst(pub String, pub u16);
impl ToString for Dst {
    fn to_string(&self) -> String {
        format!("{}:{}", self.0, self.1)
    }
}
impl Dst {
    fn to_addrs(&self) -> (String, u16) {
        (self.0.to_owned(), self.1)
    }
}

pub async fn start_server(args: RemoteArgs) -> EcliResult<()> {
    if let Action::Server { port, addr, .. } = args.server.unwrap() {
        let dst: Dst = Dst(addr, port);

        println!("Server start at {}", dst.to_string());

        let _ = server::create(dst).await;
    }
    Ok(())
}

pub use reqwest::Client;

use self::models::{LogPost200Response, LogPostRequest};

pub async fn client_action(args: RemoteArgs) -> EcliResult<()> {
    let ClientArgs {
        action_type,
        id,
        addr,
        port,
        follow,
        run_args,
    } = args.client.unwrap();

    let client = Client::new();

    let url = format!("http://{}:{}", addr, port);

    for n in id.clone().into_iter() {
        if n.is_negative() {
            return Err(EcliError::ParamErr(
                "program id should be positive".to_string(),
            ));
        }
    }

    match action_type {
        ClientActions::List => {
            let mut url = url.clone();
            url.push_str("/list");

            let rsp = client.get(url).send().await;
            info!("{:?}", &rsp);
            let rsp_json_text = rsp.unwrap().text().await.unwrap();

            let StartPostResponse::ListOfRunningTasks(rsp_msg) =
                serde_json::from_str(rsp_json_text.as_str()).expect("parse resp body fail");

            println!("{}", json!(rsp_msg));

            Ok(())
        }

        ClientActions::Start => {
            let program_name: Option<String> = PathBuf::from(run_args.file.clone())
                .file_name()
                .map(|n| n.to_string_lossy().to_string());

            let prog_data = ProgramConfigData::async_try_from(run_args).await?;

            let btf_data = match prog_data.btf_path {
                Some(d) => {
                    let mut file = File::open(d).map_err(|e| EcliError::IOErr(e)).unwrap();
                    let mut buffer = Vec::new();
                    file.read_to_end(&mut buffer).unwrap_or_default();
                    swagger::ByteArray(buffer)
                }
                None => swagger::ByteArray(Vec::new()),
            };

            let req = json!(crate::runner::server::StartReq {
                program_data_buf: Some(swagger::ByteArray(prog_data.program_data_buf)),
                program_type: Some(format!("{:?}", prog_data.prog_type)),
                program_name: program_name,
                btf_data: Some(btf_data),
                extra_params: Some(prog_data.extra_arg),
            });

            let mut url = url.clone();
            url.push_str("/start");
            let rsp = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(req.to_string())
                .send()
                .await;

            info!("{:?}", &rsp);

            let rsp_json_text = rsp
                .unwrap()
                .text()
                .await
                .expect("parse text from respond fail");

            let StartPostResponse::ListOfRunningTasks(rsp_msg) =
                serde_json::from_str(rsp_json_text.as_str()).expect("parse resp body to json fail");

            println!("{}", json!(rsp_msg));

            Ok(())
        }

        ClientActions::Stop => {
            for per_id in id {
                let req_body = json!(models::ListGet200ResponseTasksInner {
                    id: Some(per_id),
                    name: None,
                });

                let mut url = url.clone();
                url.push_str("/stop");
                let rsp = client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(req_body.to_string())
                    .send()
                    .await;

                info!("{:?}", &rsp);

                let rsp_json_text = rsp.unwrap().text().await.unwrap();

                let StopPostResponse::StatusOfStoppingTheTask(rsp_msg) =
                    serde_json::from_str(rsp_json_text.as_str())
                        .expect("parse response body to json fail");

                println!("{}", json!(rsp_msg));
            }
            Ok(())
        }

        ClientActions::Log => {
            let mut url = url.clone();
            url.push_str("/log");

            let req_body = LogPostRequest {
                id: Some(*id.get(0).unwrap()),
                follow,
            };

            macro_rules! send_req {
                () => {
                    let rsp = client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .body(json!(req_body).to_string())
                        .send()
                        .await;

                    info!("{:?}", &rsp);

                    let rsp_json_text = rsp.unwrap().text().await.unwrap();
                    let LogPostResponse::SendLog(LogPost200Response { stdout, stderr }) =
                        serde_json::from_str(rsp_json_text.as_str())
                            .expect("parse response body to json fail");

                    if let Some(s) = stdout {
                        if !s.is_empty() {
                            print!("{}", s);
                        }
                    }
                    if let Some(s) = stderr {
                        if !s.is_empty() {
                            eprint!("{}", s);
                        }
                    }
                };
            }

            if follow {
                loop {
                    send_req!();
                    time::sleep(time::Duration::from_millis(500)).await;
                }
            } else {
                send_req!();
            }

            Ok(())
        }

        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use mockito;
    use std::fs;

    use super::*;

    #[tokio::test]
    async fn test_get_file_content_from_file() {
        let file_path = "tests/test.json";
        let mut run_args = RunArgs {
            file: file_path.into(),
            ..Default::default()
        };
        let content = fs::read(file_path).unwrap();
        let result = run_args.get_file_content().await;
        assert_eq!(result.unwrap(), content);
        assert_eq!(run_args.prog_type, ProgramType::JsonEunomia);
    }

    #[tokio::test]
    async fn test_get_file_content_from_url() {
        let content = b"test content from url";

        let mut github = mockito::Server::new();

        let url = format!("{}/test", github.url());

        let mut run_args = RunArgs {
            file: url.into(),
            ..Default::default()
        };

        let github_mock = github
            .mock("GET", "/v2/test/manifests/latest")
            .with_status(201)
            .with_body(content)
            .create();

        let _ = run_args.get_file_content().await;

        github_mock.assert();
    }
}
