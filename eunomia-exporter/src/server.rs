
use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use opentelemetry::{
    global,
    metrics::Counter,
    Context, KeyValue,
};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::SystemTime;

use opentelemetry::{sdk::Resource};

fn init_meter() -> PrometheusExporter {
    opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("R", "V")]))
        .init()
}

async fn serve_req(
    cx: Context,
    req: Request<Body>,
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    println!("Receiving request at path {}", req.uri());
    let request_start = SystemTime::now();

    state.http_counter.add(100, &[KeyValue::new("key", "value")]);

    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.exporter.registry().gather();
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

struct AppState {
    exporter: PrometheusExporter,
    http_counter: Counter<u64>,
}

// #[tokio::main]
pub async fn start_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    let exporter = init_meter();
    let cx = Context::new();

    let meter = global::meter("ex.com/hyper");
    let state = Arc::new(AppState {
        exporter,
        http_counter: meter
            .u64_counter("example.http_requests_total")
            .with_description("Total number of HTTP requests made.")
            .init(),
    });

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

    server.await?;

    Ok(())
}
