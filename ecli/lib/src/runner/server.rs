//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::time::Instant;

use actix_web::{get, post, HttpRequest};
use actix_web::{web, App, HttpServer, Responder, Result};

use crate::config::*;
use crate::runner::models::{ListGet200ResponseTasksInner, LogPostRequest};
use crate::runner::response::*;
use crate::runner::utils::*;
use actix_web::error::ErrorBadRequest;
use actix_web::{get, post};
use actix_web::{web, App, HttpServer, Responder, Result};
use log::info;
use std::sync::{Arc, Mutex, MutexGuard};

pub struct AppState(Mutex<ServerData>);

impl AppState {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(ServerData::new())))
    }
    fn get_lock(&self) -> MutexGuard<ServerData> {
        self.0.lock().unwrap()
    }
}

pub async fn create(dst: crate::runner::Dst, _https: bool) -> std::io::Result<()> {
    let state = AppState::new();

    HttpServer::new(move || {
        // move counter into the closure
        App::new()
            .app_data(web::Data::from(Arc::clone(&state))) // <- register the created data
            .service(list_get)
            .service(start_post)
            .service(stop_post)
            .service(log_post)
    })
    .bind(dst.to_addrs())
    .unwrap()
    .run()
    .await
}

/// Get list of running tasks
#[get("/list")]
async fn list_get(data: web::Data<AppState>) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved List request");
    // info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());

    let server_data = data.get_lock();

    let listed_info: Vec<ListGet200ResponseTasksInner> = server_data.list_all_task();

    Ok(web::Json(ListGetResponse::gen_rsp(listed_info)))
}

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StartReq {
    pub program_data_buf: Option<swagger::ByteArray>,
    pub program_type: Option<String>,
    pub program_name: Option<String>,
    pub btf_data: Option<swagger::ByteArray>,
    pub extra_params: Option<Vec<String>>,
}

/// Start a new task
#[post("/start")]
async fn start_post(
    data: web::Data<AppState>,
    start_req: web::Json<StartReq>,
) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved start command, but has not fully been implemented");

    let startup_elem = start_req.0;

    let mut server_data = data.get_lock();

    let prog_type = startup_elem
        .program_type
        .clone()
        .unwrap()
        .parse::<ProgramType>()
        .unwrap();

    let start_result = match prog_type {
        ProgramType::WasmModule => server_data.wasm_start(startup_elem),

        ProgramType::JsonEunomia => Ok(-1), // json_start(startup_elem, &mut server_data),

        ProgramType::Tar => unimplemented!(), // tar_start(startup_elem, btf_data, &mut server_data),

        _ => unreachable!(),
    };

    Ok(web::Json(
        start_result
            .map(|id| StartPostResponse::gen_rsp(id))
            .unwrap(),
    ))
}

/// Stop a task by id or name
#[post("/stop")]
async fn stop_post(
    data: web::Data<AppState>,
    list_req: web::Json<ListGet200ResponseTasksInner>,
) -> Result<impl Responder> {
    // let context = context.clone();
    info!("Recieved stop command, but has not fully implemented");
    info!("stop with id: {:?}", &list_req.id);

    let id = list_req.id.unwrap().checked_abs().unwrap() as usize;

    let mut server_data = data.get_lock();

    let prog_info = server_data.prog_info.remove(&id);

    if prog_info.is_none() {
        return Ok(web::Json(StopPostResponse::gen_rsp("NotFound")));
    }

    Ok(web::Json(
        server_data.stop_prog(id, prog_info.unwrap()).await.unwrap(),
    ))
}

/// get log
#[post("/log")]
async fn log_post(
    data: web::Data<AppState>,
    log_req: web::Json<LogPostRequest>,
) -> Result<impl Responder> {
    let id: usize = log_req.id.unwrap().checked_abs().unwrap() as usize;
    let follow = log_req.follow;

    let server_data = data.get_lock();

    let stdout: String;
    let stderr: String;

    if follow {
        (stdout, stderr) = server_data.get_log_follow(&id).unwrap();
    } else {
        (stdout, stderr) = server_data.get_log_full(&id).unwrap();
    }

    Ok(web::Json(LogPostResponse::gen_rsp(
        Some(stdout),
        Some(stderr),
    )))
}
