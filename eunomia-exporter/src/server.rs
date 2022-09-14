use anyhow::Result;
use hyper::{
    body::Buf,
    header::{self, CONTENT_TYPE},
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use opentelemetry::Context;
use prometheus::{Encoder, TextEncoder};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;

use crate::{
    bpfmanager::BPFManagerGuard,
    config::{ExporterConfig, ProgramConfig},
    state::AppState,
};

async fn api_post_start(
    req: Request<Body>,
    program_manager: BPFManagerGuard<'_>,
    state: Arc<AppState>,
) -> Result<Response<Body>> {
    let whole_body = hyper::body::aggregate(req).await?;
    let config: ProgramConfig = serde_json::from_reader(whole_body.reader())?;
    let ret = program_manager.start(config, state).await;
    let res = match ret {
        Ok(id) => {
            let json = json!({
                "id": id,
            });
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        }
        Err(e) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(e.to_string()))
            .unwrap(),
    };
    Ok(res)
}

async fn api_post_stop(
    req: Request<Body>,
    program_manager: BPFManagerGuard<'_>,
) -> Result<Response<Body>> {
    let whole_body = hyper::body::aggregate(req).await?;
    let data: Value = serde_json::from_reader(whole_body.reader())?;
    let ret = if let Some(id) = data["id"].as_u64() {
        program_manager.stop(id as u32).await
    } else {
        Err(anyhow::anyhow!("id not found"))
    };
    let res = match ret {
        Ok(_) => Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(""))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(e.to_string()))
            .unwrap(),
    };
    Ok(res)
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
        (&Method::POST, "/start") => api_post_start(req, program_manager, state).await?,
        (&Method::POST, "/stop") => api_post_stop(req, program_manager).await?,
        (&Method::GET, "/list") => {
            let lists = program_manager.list().await;
            Response::builder()
                .status(200)
                .body(Body::from(serde_json::to_string(&lists)?))?
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
