use std::{sync::Arc, time::Duration};

use anyhow::Result;
use lib::runner::server::{list_get, log_post, start_post, stop_post, AppState, StartReq};
use tokio;
// mod common;
// use common::start_server;
use tokio::time::sleep;
use tracing::log::info;

use actix_web::{test, App, HttpResponse, Responder};

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

mod tests {
    use std::fs;

    use super::*;
    use actix_web::{http, test};
    use lib::{
        config::ProgramType,
        runner::{
            models::{self, LogPostRequest},
            server::{list_get, log_post, start_post, stop_post, StartReq},
        },
    };
    use serde_json::json;

    #[actix_web::test]
    async fn test_server_api_stop() {
        init();
        let state = AppState::new();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::from(Arc::clone(&state)))
                .service(start_post)
                .service(stop_post),
        )
        .await;

        let req_start = test::TestRequest::post()
            .uri("/start")
            .set_json(json!(StartReq {
                program_data_buf: Some(swagger::ByteArray(
                    fs::read("./tests/bootstrap.wasm").unwrap()
                )),
                program_type: Some("WasmModule".to_string()),
                program_name: Some("bootstrap.wasm".to_string()),
                btf_data: Some(swagger::ByteArray(vec![])),
                extra_params: Some(vec![]),
            }))
            .to_request();

        let req_stop = test::TestRequest::post()
            .uri("/stop")
            .set_json(json!(models::ListGet200ResponseTasksInner {
                id: Some(0),
                name: None,
            }))
            .to_request();

        let resp_start = test::call_service(&app, req_start).await;

        let resp_stop = test::call_service(&app, req_stop).await;

        info!("{:?}", resp_start.status());
        info!("{:?}", resp_stop.status());
        assert!(resp_start.status().is_success());
        assert!(resp_stop.status().is_success());
    }

    #[actix_web::test]
    async fn test_server_api_log() {
        init();
        let state = AppState::new();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::from(Arc::clone(&state)))
                .service(start_post)
                .service(log_post),
        )
        .await;

        let req_start = test::TestRequest::post()
            .uri("/start")
            .set_json(json!(StartReq {
                program_data_buf: Some(swagger::ByteArray(
                    fs::read("./tests/bootstrap.wasm").unwrap()
                )),
                program_type: Some("WasmModule".to_string()),
                program_name: Some("bootstrap.wasm".to_string()),
                btf_data: Some(swagger::ByteArray(vec![])),
                extra_params: Some(vec![]),
            }))
            .to_request();

        let req_log = test::TestRequest::post()
            .uri("/log")
            .set_json(json!(LogPostRequest {
                id: Some(0),
                follow: false,
            }))
            .to_request();
        let resp_start = test::call_service(&app, req_start).await;

        let resp_log = test::call_service(&app, req_log).await;

        info!("{:?}", resp_start.status());
        info!("{:?}", resp_log.status());

        assert!(resp_start.status().is_success());
        assert!(resp_log.status().is_success());
    }

    #[actix_web::test]
    async fn test_server_api_start() {
        init();
        let state = AppState::new();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::from(Arc::clone(&state)))
                .service(start_post),
        )
        .await;

        let req_start = test::TestRequest::post()
            .uri("/start")
            .set_json(json!(StartReq {
                program_data_buf: Some(swagger::ByteArray(
                    fs::read("./tests/bootstrap.wasm").unwrap()
                )),
                program_type: Some("WasmModule".to_string()),
                program_name: Some("bootstrap.wasm".to_string()),
                btf_data: Some(swagger::ByteArray(vec![])),
                extra_params: Some(vec![]),
            }))
            .to_request();

        let resp_start = test::call_service(&app, req_start).await;
        info!("{:?}", resp_start.status());
        assert!(resp_start.status().is_success());
    }

    #[actix_web::test]
    async fn test_server_api_list() {
        init();
        let state = AppState::new();
        let app = test::init_service(
            App::new()
                .app_data(actix_web::web::Data::from(Arc::clone(&state)))
                .service(list_get),
        )
        .await;

        let req_list = test::TestRequest::get().uri("/list").to_request();

        let resp_list = test::call_service(&app, req_list).await;

        assert!(resp_list.status().is_success());
    }
}
