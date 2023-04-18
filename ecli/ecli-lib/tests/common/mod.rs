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
    ecli_lib::runner::remote::create(addr.to_string(), false, shutdown_rx).await;
}

pub fn is_port_open(address: &str) -> bool {
    if std::net::TcpStream::connect(address).is_ok() {
        return true;
    }
    false
}

pub mod client_tests {

    use ecli_lib::client_action;
    use ecli_lib::runner::{ClientArgs, RunArgs};
    use ecli_lib::RemoteArgs;

    pub async fn list() {
        let args = RemoteArgs {
            client: Some(ClientArgs {
                action_type: ecli_lib::runner::ClientActions::List,
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
                action_type: ecli_lib::runner::ClientActions::Stop,
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
                action_type: ecli_lib::runner::ClientActions::Start,
                id: vec![0],
                run_args: RunArgs {
                    // test transport of file
                    file: "tests/test.json".to_string(),
                    prog_type: ecli_lib::config::ProgramType::JsonEunomia,
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
}
