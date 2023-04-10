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

use log::{debug, info};
use openapi_client::models::{LogPost200Response, LogPostRequest};
use openapi_client::LogPostResponse;
use serde_json::json;
use swagger::{make_context, Has, XSpanIdString};
use tokio::time;
use url::Url;

pub use crate::ClientSubCommand;
use crate::{
    config::{ProgramConfigData, ProgramType},
    error::{EcliError, EcliResult},
    json_runner::json::handle_json,
    oci::{default_schema_port, parse_img_url, wasm_pull},
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

#[allow(unused_imports)]
use openapi_client::*;

pub mod server;
pub mod utils;
use server::*;

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
    pub endpoint: String,
    pub port: u16,
    pub secure: bool,
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

pub async fn start_server(args: RemoteArgs) -> EcliResult<()> {
    if let Action::Server {
        port, addr, secure, ..
    } = args.server.unwrap()
    {
        let addr: String = format!("{addr}:{port}");
        println!("Server start at {addr}");
        let (_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        server::create(addr, secure, shutdown_rx).await;
    }
    Ok(())
}

type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);

pub async fn client_action(args: RemoteArgs) -> EcliResult<()> {
    let ClientArgs {
        action_type,
        id,
        endpoint,
        port,
        secure,
        run_args,
    } = args.client.unwrap();

    if secure {
        return Err(EcliError::Other(format!(
            "Transport with https not implement yet!"
        )));
    }

    let url = format!(
        "{}://{}:{}",
        if secure { "https" } else { "http" },
        endpoint,
        port
    );

    let context: ClientContext = make_context!(
        ContextBuilder,
        EmptyContext,
        None as Option<AuthData>,
        XSpanIdString::default()
    );

    let client: Box<dyn ApiNoContext<ClientContext>> = if secure {
        // Using Simple HTTPS
        let client = Box::new(Client::try_new_https(&url).expect("Failed to create HTTPS client"));
        Box::new(client.with_context(context))
    } else {
        // Using HTTP
        let client = Box::new(Client::try_new_http(&url).expect("Failed to create HTTP client"));
        Box::new(client.with_context(context))
    };

    match action_type {
        ClientActions::List => {
            let result = client.list_get().await;
            let ListGetResponse::ListOfRunningTasks(rsp_msg) = result.as_ref().unwrap();
            println!("{}", json!(rsp_msg));
            info!(
                "{:?} (X-Span-ID: {:?})",
                result,
                (client.context() as &dyn Has<XSpanIdString>).get().clone()
            );

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

            let result = client
                .start_post(
                    Some(swagger::ByteArray(prog_data.program_data_buf)),
                    Some(format!("{:?}", prog_data.prog_type)),
                    program_name,
                    Some(btf_data),
                    Some(&prog_data.extra_arg),
                )
                .await;

            let StartPostResponse::ListOfRunningTasks(rsp_msg) = result.as_ref().unwrap();

            println!("{}", json!(rsp_msg));
            info!(
                "{:?} (X-Span-ID: {:?})",
                result,
                (client.context() as &dyn Has<XSpanIdString>).get().clone()
            );
            Ok(())
        }

        ClientActions::Stop => {
            for per_id in id {
                let inner = models::ListGet200ResponseTasksInner {
                    id: Some(per_id),
                    name: None,
                };

                let result = client.stop_post(inner).await;

                let StopPostResponse::StatusOfStoppingTheTask(rsp_msg) = result.as_ref().unwrap();
                println!("{}", json!(rsp_msg));
                info!(
                    "{:?} (X-Span-ID: {:?})",
                    result,
                    (client.context() as &dyn Has<XSpanIdString>).get().clone()
                );
            }
            Ok(())
        }

        ClientActions::Log => {
            loop {
                let post_req = LogPostRequest { id: Some(id[0]) };
                let result = client.log_post(post_req).await;

                // println!("{:?} from endpoint:  {endpoint}:{port}", result);
                let LogPostResponse::SendLog(LogPost200Response { stdout, stderr }) =
                    result.unwrap();

                if let Some(s) = stdout {
                    if !s.is_empty() {
                        println!("{}", s);
                    }
                }
                if let Some(s) = stderr {
                    if !s.is_empty() {
                        eprintln!("{}", s);
                    }
                }
                time::sleep(time::Duration::from_secs(1)).await;
            }

            #[allow(unused)]
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
