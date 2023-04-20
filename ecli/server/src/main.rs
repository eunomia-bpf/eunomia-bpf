//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use clap::Parser;
use flexi_logger::opt_format;
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn, Service},
    Body, Request, Server,
};
use log::{info, warn};

use std::{convert::Infallible, net::SocketAddr, str::FromStr, time::Instant};

use ecli_lib::{
    error::{Error, Result},
    runner::server_http::{EcliHttpServerAPI, HttpServerState},
};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    config: Option<String>,
    #[clap(short, long, help = "Port to bind", default_value = "8527")]
    port: u16,
    #[arg(short, long, default_value = "127.0.0.1", help = "Address to bind")]
    addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")
        .map_err(|e| Error::Log(format!("Failed to create logger: {}", e)))?
        .format(opt_format)
        .start()
        .map_err(|e| Error::Log(format!("Failed to start logger: {}", e)))?;

    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel::<()>(1);
    if let Err(e) = ctrlc::set_handler(move || {
        info!("Shutting down server..");
        stop_tx.blocking_send(()).unwrap();
    }) {
        warn!("Failed to bind exit handler: {}", e);
    }
    let args = Args::parse();
    let addr = SocketAddr::from_str(&format!("{}:{}", args.addr, args.port))
        .map_err(|e| Error::Other(format!("Failed to parse socket addr: {}", e)))?;
    let app_state = HttpServerState::default();
    let server = Server::bind(&addr);
    let server = server.serve(make_service_fn(move |conn: &AddrStream| {
        let remote_ip = conn.remote_addr().ip();
        let app_state = app_state.clone();
        let mut service = ecli_server_codegen::Service::new(EcliHttpServerAPI {});
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let app_state = app_state.clone();
                let client_ip = req
                    .headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| remote_ip.to_string());
                let method = req.method().to_string();
                let uri = req
                    .uri()
                    .path_and_query()
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let start_time = Instant::now();
                let fut = service.call((req, app_state));
                async move {
                    let resp = fut.await;
                    match &resp {
                        Ok(resp) => {
                            let status_code = resp.status().to_string();
                            let elapsed = start_time.elapsed();
                            info!(
                                "{} {} {} {} {:0>3}s",
                                client_ip,
                                method,
                                uri,
                                status_code,
                                elapsed.as_millis() as f64 / 1000.0
                            )
                        }
                        Err(_) => {}
                    }
                    resp
                }
            }))
        }
    }));
    info!("Serving at {}:{}", args.addr, args.port);
    server
        .with_graceful_shutdown(async move {
            stop_rx.recv().await;
        })
        .await
        .map_err(|e| Error::Other(format!("Failed to serve: {}", e)))?;
    Ok(())
}
