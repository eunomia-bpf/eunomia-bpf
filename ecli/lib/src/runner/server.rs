//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::config::*;
use crate::runner::utils::*;
use async_trait::async_trait;
use blake3::hash;
use log::info;
use openapi_client::models::ListGet200ResponseTasksInner;
use openapi_client::server::MakeService;
use openapi_client::{
    models::*, Api, ListGetResponse, LogPostResponse, StartPostResponse, StopPostResponse,
};
use std::sync::Arc;
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::ApiError;
pub use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};
use tokio::sync::oneshot::Receiver;
use tokio::sync::Mutex;

pub async fn create(addr: String, _https: bool, shutdown_rx: Receiver<()>) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server_data = Arc::new(Mutex::new(ServerData::new()));

    let server = Server::new(server_data);

    let service = MakeService::new(server);

    let service = MakeAllowAllAuthenticator::new(service, "cosmo");

    let service = openapi_client::server::context::MakeAddContext::<_, EmptyContext>::new(service);
    // Using HTTP
    hyper::server::Server::bind(&addr)
        .serve(service)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        })
        .await
        .unwrap()
}

#[async_trait]
impl<C> Api<C> for Server<C>
where
    C: Has<XSpanIdString> + Send + Sync,
{
    /// Get list of running tasks
    async fn list_get(&self, context: &C) -> Result<ListGetResponse, ApiError> {
        let context = context.clone();
        info!("Recieved List request");
        info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());

        let server_data = self.data.lock().await;

        let listed_info: Vec<ListGet200ResponseTasksInner> = server_data.list_all_task();

        ListGetResponse::gen_list_resp(listed_info)
    }

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        program_name: Option<String>,
        btf_data: Option<swagger::ByteArray>,
        extra_params: Option<&Vec<String>>,
        context: &C,
    ) -> Result<StartPostResponse, ApiError> {
        let context = context.clone();
        info!("Recieved start command, but has not fully been implemented");
        info!(
            "start_post({}, {:?}, {}, {:?}) - X-Span-ID: {:?}",
            hash(program_data_buf.as_ref().unwrap().as_slice()),
            program_type,
            if !btf_data.as_ref().unwrap().is_empty() {
                hash(btf_data.as_ref().unwrap().as_slice()).to_string()
            } else {
                String::default()
            },
            extra_params,
            context.get().0.clone()
        );

        let mut server_data = self.data.lock().await;

        let prog_type = program_type.unwrap().parse::<ProgramType>().unwrap();

        let startup_elem = StartupElements::new(program_name, program_data_buf, extra_params);

        let start_result = match prog_type {
            ProgramType::WasmModule => server_data.wasm_start(startup_elem),

            ProgramType::JsonEunomia => Ok(-1), // json_start(startup_elem, &mut server_data),

            ProgramType::Tar => unimplemented!(), // tar_start(startup_elem, btf_data, &mut server_data),

            _ => unreachable!(),
        };

        start_result.map(|id| StartPostResponse::gen_start_resp(id))
    }

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: ListGet200ResponseTasksInner,
        context: &C,
    ) -> Result<StopPostResponse, ApiError> {
        let context = context.clone();
        info!("Recieved stop command, but has not fully implemented");
        info!("stop with id: {:?}", &list_get200_response_tasks_inner.id);

        info!(
            "stop_post({:?}) - X-Span-ID: {:?}",
            list_get200_response_tasks_inner,
            context.get().0.clone()
        );

        let id = list_get200_response_tasks_inner.id.unwrap();

        let mut server_data = self.data.lock().await;

        let prog_info = server_data
            .prog_info
            .remove(&(id.checked_abs().unwrap() as usize));

        if prog_info.is_none() {
            return StopPost200Response::gen_stop_resp("NotFound");
        }

        server_data.stop_prog(id, prog_info.unwrap()).await
    }

    /// get log
    async fn log_post(
        &self,
        log_post_request: LogPostRequest,
        context: &C,
    ) -> Result<LogPostResponse, ApiError> {
        let context = context.clone();
        info!(
            "log_post({:?}) - X-Span-ID: {:?}",
            log_post_request,
            context.get().0.clone()
        );

        let id = log_post_request.id.unwrap().checked_abs().unwrap() as usize;

        let mut server_data = self.data.lock().await;

        let prog_type = server_data.get_type_of(id);

        if prog_type.is_none() {
            return Err(ApiError("NotFound".to_string()));
        }

        let (out, err) = match prog_type.unwrap() {
            ProgramType::WasmModule => {
                let prog = server_data.wasm_tasks.get_mut(&id).unwrap();

                let out = prog.log_msg.get_stdout();
                let err = prog.log_msg.get_stderr();

                (out, err)
            }
            _ => unimplemented!(),
        };

        LogPostResponse::gen_log_resp(Some(out), Some(err))
    }
}
