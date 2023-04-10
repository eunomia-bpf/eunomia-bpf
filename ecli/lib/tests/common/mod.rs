use tokio::sync::oneshot::Receiver;
use tracing::log::info;

#[allow(unused)]
pub const RETRY_MAX: u16 = 3;

use crate::ADDRESS;

pub async fn run_eserver() -> tokio::sync::oneshot::Sender<()> {
    info!("starting server at {ADDRESS}...");
    let (tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let _ = tokio::spawn(start_server(ADDRESS, shutdown_rx));

    info!("returning sender...");
    tx
}

pub async fn start_server(addr: &str, shutdown_rx: Receiver<()>) {
    lib::runner::server::create(addr.to_string(), false, shutdown_rx).await;
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
    use openapi_client::{
        models::{LogPost200Response, LogPostRequest},
        ApiNoContext, Client, ContextWrapperExt, LogPostResponse,
    };
    use swagger::Push;
    use swagger::{make_context, AuthData, ContextBuilder, EmptyContext, XSpanIdString};
    use tokio::time;

    pub async fn list() {
        let args = RemoteArgs {
            client: Some(ClientArgs {
                action_type: runner::ClientActions::List,
                id: vec![0],
                run_args: RunArgs {
                    ..Default::default()
                },
                endpoint: "127.0.0.1".to_string(),
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
                endpoint: "127.0.0.1".to_string(),
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
                endpoint: "127.0.0.1".to_string(),
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
                endpoint: "127.0.0.1".to_string(),
                port: 8527,
                secure: false,
            }),
            server: None,
        };

        client_action(args).await.unwrap()
    }

    pub async fn log() {
        type ClientContext = swagger::make_context_ty!(
            ContextBuilder,
            EmptyContext,
            Option<AuthData>,
            XSpanIdString
        );
        let context: ClientContext = make_context!(
            ContextBuilder,
            EmptyContext,
            None as Option<AuthData>,
            XSpanIdString::default()
        );

        let url: String = String::from_str("http://127.0.0.1:8527").unwrap();

        let client: Box<dyn ApiNoContext<ClientContext>> = {
            let client =
                Box::new(Client::try_new_http(&url).expect("Failed to create HTTP client"));
            Box::new(client.with_context(context))
        };

        let post_req = LogPostRequest { id: Some(0) };
        let result = client.log_post(post_req).await;

        let LogPostResponse::SendLog(LogPost200Response { stdout, stderr }) = result.unwrap();

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
}
