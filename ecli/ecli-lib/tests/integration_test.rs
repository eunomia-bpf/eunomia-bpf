use anyhow::Result;
use tokio;
mod common;
use common::run_eserver;
use std::time::Duration;
use tokio::time::sleep;
use tracing::log::info;

use tracing_subscriber::EnvFilter;

pub const ADDRESS: &str = "127.0.0.1:8527";

fn init() {
    let level = "info";
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::from(level)),
        )
        .try_init();
}

#[tokio::test]
async fn api_test() -> Result<()> {
    init();

    info!("test if server start successfully:");
    let tx = run_eserver().await;

    info!("waiting for server start");
    sleep(Duration::from_secs(3)).await;

    info!("if port opened");
    assert!(common::is_port_open(ADDRESS));

    common::client_tests::list().await;

    common::client_tests::stop().await;

    common::client_tests::start().await;

    sleep(Duration::from_secs(2)).await;

    info!("server shutdown");
    let _ = tx.send(());
    Ok(())
}
