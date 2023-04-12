use std::future::Future;

use tokio::sync::oneshot::Receiver;
use tracing::log::info;

#[allow(unused)]
pub const RETRY_MAX: u16 = 3;

use crate::ADDRESS;

pub async fn start_server() -> impl Future<Output = Result<(), std::io::Error>> {
    let addr = "127.0.0.1".to_string();
    lib::runner::server::create(lib::runner::Dst(addr, 8527), false)
}

pub fn is_port_open(address: &str) -> bool {
    if std::net::TcpStream::connect(address).is_ok() {
        return true;
    }
    false
}

pub mod client_tests {

    use std::str::FromStr;

    use lib::{
        config,
        runner::{self, client_action, ClientArgs, RemoteArgs, RunArgs},
    };
    use serde_json::json;
    use tracing::info;

    pub async fn list() {
        let args = RemoteArgs {
            client: Some(ClientArgs {
                action_type: runner::ClientActions::List,
                id: vec![0],
                run_args: RunArgs {
                    ..Default::default()
                },
                addr: "127.0.0.1".to_string(),
                port: 8527,
                secure: false,
            }),
            server: None,
        };

        client_action(args).await.unwrap()
    }
    pub async fn stop() {
        let args = RemoteArgs {
            client: Some(ClientArgs {
                action_type: runner::ClientActions::Stop,
                id: vec![1, 2, 3, 4, 5],
                run_args: RunArgs {
                    ..Default::default()
                },
                addr: "127.0.0.1".to_string(),
                port: 8527,
                secure: false,
            }),
            server: None,
        };

        client_action(args).await.unwrap()
    }

    pub async fn start() {
        let args = RemoteArgs {
            client: Some(ClientArgs {
                action_type: runner::ClientActions::Start,
                id: vec![0],
                run_args: RunArgs {
                    // test transport of file
                    file: "tests/test.json".to_string(),
                    prog_type: config::ProgramType::JsonEunomia,
                    ..Default::default()
                },
                addr: "127.0.0.1".to_string(),
                port: 8527,
                secure: false,
            }),
            server: None,
        };

        client_action(args).await.unwrap()
    }
    pub async fn start_real_wasm_prog() {
        let args = RemoteArgs {
            client: Some(ClientArgs {
                action_type: runner::ClientActions::Start,
                id: vec![0],
                run_args: RunArgs {
                    // test transport of file
                    file: "tests/bootstrap.wasm".to_string(),
                    prog_type: config::ProgramType::WasmModule,
                    ..Default::default()
                },
                addr: "127.0.0.1".to_string(),
                port: 8527,
                secure: false,
            }),
            server: None,
        };

        client_action(args).await.unwrap()
    }

    pub async fn log() {
        let mut url: String = String::from_str("http://127.0.0.1:8527").unwrap();

        let post_req = LogPostRequest {
            id: Some(0),
            follow: false,
        };

        let client = Client::new();
        url.push_str("/log");

        let req_body = LogPostRequest {
            id: Some(0),
            follow: true,
        };

        let rsp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(json!(req_body).to_string())
            .send()
            .await;

        info!("{:?}", &rsp);

        let rsp_json_text = rsp.unwrap().text().await.unwrap();
        let LogPostResponse::SendLog(LogPost200Response { stdout, stderr }) =
            serde_json::from_str(rsp_json_text.as_str()).expect("parse response body fail");

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
    }
}
