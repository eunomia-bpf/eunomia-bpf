use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use opentelemetry::Context;
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use std::time::SystemTime;
use std::{convert::Infallible, fs, time::Duration};
use tokio::time::Instant;

use crate::{
    config::ExporterConfig,
    state::{AppState, BPFProgramManager, BPFProgramState},
};

async fn run_ebpf_program(
    state: Arc<AppState>,
    json_data: String,
    name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = Instant::now();

    let mut ebpf_program = BPFProgramState::new(json_data, "hello".to_string())?;
    ebpf_program.run(Arc::downgrade(&state))?;
    let bpf_handler = Arc::new(ebpf_program);
    let new_handler = bpf_handler.clone();
    let handler = state.get_runtime().spawn(async move {
        print!("Running ebpf program");
        bpf_handler.wait_and_export()
    });
    let elapsed_time = now.elapsed();
    println!(
        "Running slow_function() took {} ms.",
        elapsed_time.as_millis()
    );
    new_handler.stop();
    let _ = state.get_runtime().block_on(handler)?;
    Ok(())
}

async fn serve_req(
    cx: Context,
    req: Request<Body>,
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    println!("Receiving request at path {}", req.uri());
    let request_start = SystemTime::now();

    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .status(200)
                .header(CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buffer))
                .unwrap()
        }
        (&Method::GET, "/") => Response::builder()
            .status(200)
            .body(Body::from("Hello World"))
            .unwrap(),
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
    let state = Arc::new(AppState::init(config));

    let manager = Arc::new(BPFProgramManager::new());
    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.
    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        let cx = cx.clone();
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                serve_req(cx.clone(), req, state.clone())
            }))
        }
    });
    let addr = ([127, 0, 0, 1], 8526).into();
    let server = Server::bind(&addr).serve(make_svc);
    println!("Listening on http://{}", addr);
    // server.await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config;

    use super::*;

    #[test]
    fn test_async_start_ebpf_program() {
        let config = config::ExporterConfig {};
        let state = Arc::new(AppState::init(&config));

        let json_data = fs::read_to_string("tests/package.json").unwrap();
        let now = Instant::now();

        let mut ebpf_program = BPFProgramState::new(json_data, "hello".to_string()).unwrap();
        ebpf_program.run(Arc::downgrade(&state)).unwrap();
        let bpf_handler = Arc::new(ebpf_program);
        let new_handler = bpf_handler.clone();
        let handler = state.get_runtime().spawn(async move {
            print!("Running ebpf program");
            bpf_handler.wait_and_export()
        });
        let elapsed_time = now.elapsed();
        println!(
            "Running slow_function() took {} ms.",
            elapsed_time.as_millis()
        );
        std::thread::sleep(Duration::from_millis(750));
        println!("Finished time-consuming task.");
        new_handler.stop();
        new_handler.stop();
        let _ = state.get_runtime().block_on(handler).unwrap();
    }
}
