use anyhow::Result;
use hyper::{
    body::Buf,
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use opentelemetry::Context;
use prometheus::{Encoder, TextEncoder};
use serde_json::Value;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    bpfprog::BPFProgramManager,
    config::{ExporterConfig, ProgramConfig},
    state::AppState,
};

#[derive(Clone)]
struct BPFManagerGuard<'a> {
    guard: Arc<Mutex<BPFProgramManager<'a>>>,
}

impl<'a> BPFManagerGuard<'a> {
    pub fn new(config: &ExporterConfig, state: Arc<AppState>) -> Result<BPFManagerGuard<'a>> {
        let mut program_manager = BPFProgramManager::new();
        program_manager.start_programs_for_exporter(config, state)?;
        Ok(BPFManagerGuard {
            guard: Arc::new(Mutex::new(program_manager)),
        })
    }
    pub async fn start(&self, config: ProgramConfig, state: Arc<AppState>) -> Result<u32> {
        let mut guard = self.guard.lock().await;
        guard.add_bpf_prog(&config, state)
    }
    pub async fn stop(&self, id: u32) -> Result<()> {
        let mut guard = self.guard.lock().await;
        guard.remove_bpf_prog(id)
    }
    pub async fn list(&self) -> Vec<(u32, String)> {
        let guard = self.guard.lock().await;
        guard.list_all_progs()
    }
}

async fn serve_req(
    _cx: Context,
    req: Request<Body>,
    state: Arc<AppState>,
    program_manager: BPFManagerGuard<'_>,
) -> Result<Response<Body>> {
    println!("Receiving request at path {}", req.uri());

    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.gather();
            encoder.encode(&metric_families, &mut buffer)?;

            Response::builder()
                .status(200)
                .header(CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buffer))?
        }
        (&Method::POST, "/start") => {
            let whole_body = hyper::body::aggregate(req).await?;
            let config: ProgramConfig = serde_json::from_reader(whole_body.reader())?;
            program_manager.start(config, state).await?;
            Response::builder().status(200).body(Body::from("{}"))?
        }
        (&Method::GET, "/list") => {
            let lists = program_manager.list().await;
            Response::builder()
                .status(200)
                .body(Body::from(serde_json::to_string(&lists)?))?
        }
        (&Method::POST, "/stop") => {
            let whole_body = hyper::body::aggregate(req).await?;
            let data: Value = serde_json::from_reader(whole_body.reader())?;
            if let Some(id) = data["id"].as_u64() {
                program_manager.stop(id as u32).await?;
                Response::builder().status(200).body(Body::from("{}"))?
            } else {
                Response::builder().status(400).body(Body::from("{}"))?
            }
        }
        _ => Response::builder()
            .status(404)
            .body(Body::from("Missing Page"))
            .unwrap(),
    };
    Ok(response)
}

// #[tokio::main]
pub fn start_server(
    config: &ExporterConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cx = Context::new();
    let state = Arc::new(AppState::init());
    let new_state = state.clone();
    let manager = BPFManagerGuard::new(config, new_state.clone())?;

    let _ = new_state.get_runtime().block_on(async move {
        let make_svc = make_service_fn(move |_conn| {
            let state = state.clone();
            let cx = cx.clone();
            let manager = manager.clone();
            // This is the `Service` that will handle the connection.
            // `service_fn` is a helper to convert a function that
            // returns a Response into a `Service`.
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    serve_req(cx.clone(), req, state.clone(), manager.clone())
                }))
            }
        });

        let addr = ([127, 0, 0, 1], 8526).into();

        let server = Server::bind(&addr).serve(make_svc);

        println!("Listening on http://{}", addr);
        server.await
    });
    Ok(())
}
