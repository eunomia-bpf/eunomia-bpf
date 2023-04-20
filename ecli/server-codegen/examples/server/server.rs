//! Main library entry point for ecli_server_codegen implementation.

#![allow(unused_imports)]

use async_trait::async_trait;
use futures::{future, Stream, StreamExt, TryFutureExt, TryStreamExt};
use hyper::server::conn::Http;
use hyper::service::Service;
use log::info;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::EmptyContext;
use swagger::{Has, XSpanIdString};
use tokio::net::TcpListener;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::{Ssl, SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

use ecli_server_codegen::models;

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: &str, https: bool) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server = Server::new();

    let service = MakeService::new(server);

    let service = MakeAllowAllAuthenticator::new(service, "cosmo");

    #[allow(unused_mut)]
    let mut service =
        ecli_server_codegen::server::context::MakeAddContext::<_, EmptyContext>::new(service);

    if https {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "ios"))]
        {
            unimplemented!("SSL is not implemented for the examples on MacOS, Windows or iOS");
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
        {
            let mut ssl = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
                .expect("Failed to create SSL Acceptor");

            // Server authentication
            ssl.set_private_key_file("examples/server-key.pem", SslFiletype::PEM)
                .expect("Failed to set private key");
            ssl.set_certificate_chain_file("examples/server-chain.pem")
                .expect("Failed to set certificate chain");
            ssl.check_private_key()
                .expect("Failed to check private key");

            let tls_acceptor = ssl.build();
            let tcp_listener = TcpListener::bind(&addr).await.unwrap();

            loop {
                if let Ok((tcp, _)) = tcp_listener.accept().await {
                    let ssl = Ssl::new(tls_acceptor.context()).unwrap();
                    let addr = tcp.peer_addr().expect("Unable to get remote address");
                    let service = service.call(addr);

                    tokio::spawn(async move {
                        let tls = tokio_openssl::SslStream::new(ssl, tcp).map_err(|_| ())?;
                        let service = service.await.map_err(|_| ())?;

                        Http::new()
                            .serve_connection(tls, service)
                            .await
                            .map_err(|_| ())
                    });
                }
            }
        }
    } else {
        // Using HTTP
        hyper::server::Server::bind(&addr)
            .serve(service)
            .await
            .unwrap()
    }
}

#[derive(Copy, Clone)]
pub struct Server<C> {
    marker: PhantomData<C>,
}

impl<C> Server<C> {
    pub fn new() -> Self {
        Server {
            marker: PhantomData,
        }
    }
}

use ecli_server_codegen::server::MakeService;
use ecli_server_codegen::{
    Api, GetTaskListResponse, GetTaskLogByIdResponse, PauseTaskByIdResponse,
    ResumeTaskByIdResponse, StartTaskResponse, StopTaskByIdResponse,
};
use std::error::Error;
use swagger::ApiError;

#[async_trait]
impl<C> Api<C> for Server<C>
where
    C: Has<XSpanIdString> + Send + Sync,
{
    /// Get list of running tasks
    async fn get_task_list(&self, context: &C) -> Result<GetTaskListResponse, ApiError> {
        let context = context.clone();
        info!("get_task_list() - X-Span-ID: {:?}", context.get().0.clone());
        Err(ApiError("Generic failure".into()))
    }

    /// get log
    async fn get_task_log_by_id(
        &self,
        get_task_log_request: models::GetTaskLogRequest,
        context: &C,
    ) -> Result<GetTaskLogByIdResponse, ApiError> {
        let context = context.clone();
        info!(
            "get_task_log_by_id({:?}) - X-Span-ID: {:?}",
            get_task_log_request,
            context.get().0.clone()
        );
        Err(ApiError("Generic failure".into()))
    }

    /// Pause a task by id
    async fn pause_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &C,
    ) -> Result<PauseTaskByIdResponse, ApiError> {
        let context = context.clone();
        info!(
            "pause_task_by_id({:?}) - X-Span-ID: {:?}",
            simple_id_request,
            context.get().0.clone()
        );
        Err(ApiError("Generic failure".into()))
    }

    /// Resume a task by id
    async fn resume_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &C,
    ) -> Result<ResumeTaskByIdResponse, ApiError> {
        let context = context.clone();
        info!(
            "resume_task_by_id({:?}) - X-Span-ID: {:?}",
            simple_id_request,
            context.get().0.clone()
        );
        Err(ApiError("Generic failure".into()))
    }

    /// Start a new task
    async fn start_task(
        &self,
        start_task_request: models::StartTaskRequest,
        context: &C,
    ) -> Result<StartTaskResponse, ApiError> {
        let context = context.clone();
        info!(
            "start_task({:?}) - X-Span-ID: {:?}",
            start_task_request,
            context.get().0.clone()
        );
        Err(ApiError("Generic failure".into()))
    }

    /// Stop a task by id
    async fn stop_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &C,
    ) -> Result<StopTaskByIdResponse, ApiError> {
        let context = context.clone();
        info!(
            "stop_task_by_id({:?}) - X-Span-ID: {:?}",
            simple_id_request,
            context.get().0.clone()
        );
        Err(ApiError("Generic failure".into()))
    }
}
