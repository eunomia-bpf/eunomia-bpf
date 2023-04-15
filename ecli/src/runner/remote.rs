use crate::config::*;
use crate::error::{EcliError, EcliResult};
use crate::json_runner::json::handle_json;
use crate::wasm_bpf_runner::wasm::handle_wasm;
use async_trait::async_trait;
use eunomia_rs::TempDir;
use hyper::server::conn::Http;
use hyper::service::Service;
use log::info;
use openapi_client::models::ListGet200ResponseTasksInner;
use openapi_client::server::MakeService;
use openapi_client::{models::*, Api, ListGetResponse, StartPostResponse, StopPostResponse};
use std::fs::write;
use std::marker::PhantomData;
use std::write;
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::ApiError;
pub use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};
use tokio::net::TcpListener;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod};

pub type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: &str, https: bool) {
    let addr = addr.parse().expect("Failed to parse bind address");

    let server = Server::new();

    let service = MakeService::new(server);

    let service = MakeAllowAllAuthenticator::new(service, "cosmo");

    #[allow(unused_mut)]
    let mut service =
        openapi_client::server::context::MakeAddContext::<_, EmptyContext>::new(service);

    if https {
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

#[derive(Clone)]
pub struct Server<C> {
    // tasks: HashMap<usize, Worker>,
    marker: PhantomData<C>,
}

impl<C> Server<C> {
    pub fn new() -> Self {
        Server {
            // tasks: HashMap::new(),
            marker: PhantomData,
        }
    }
}

#[allow(unused)]
pub async fn endpoint_start(data: ProgramConfigData) -> EcliResult<()> {
    match data.prog_type {
        ProgramType::JsonEunomia => handle_json(data),
        ProgramType::WasmModule => handle_wasm(data),
        ProgramType::Tar => Err(EcliError::BpfError(format!(
            "Transporting btf path data to remote is not implemented"
        ))),
        _ => unreachable!(),
    }
}

// server behavior not implemented

#[async_trait]
impl<C> Api<C> for Server<C>
where
    C: Has<XSpanIdString> + Send + Sync,
{
    /// Get list of running tasks
    async fn list_get(&self, context: &C) -> Result<ListGetResponse, ApiError> {
        let context = context.clone();
        info!("Recieved List request, but has not been implemented");
        info!("list_get() - X-Span-ID: {:?}", context.get().0.clone());
        // Err(ApiError("This server behavior not implemented".into()))
        Ok(ListGetResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("unimplemented".into()),
            tasks: None,
        }))
    }

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        btf_data: Option<swagger::ByteArray>,
        extra_params: Option<&Vec<String>>,
        context: &C,
    ) -> Result<StartPostResponse, ApiError> {
        let context = context.clone();
        info!("Recieved start command, but has not been implemented");
        info!(
            "start_post({:?}, {:?}, {:?}, {:?}) - X-Span-ID: {:?}",
            program_data_buf,
            program_type,
            btf_data,
            extra_params,
            context.get().0.clone()
        );

        let tmp_dir = TempDir::new();

        let tmp_data_dir = if let Ok(p) = tmp_dir {
            p
        } else {
            return Err(ApiError("Could not create tmp dir".into()));
        };

        // store btf_data
        let btf_data_file_path = tmp_data_dir.path().join("btf_data");
        if let Some(b) = btf_data {
            if write(&btf_data_file_path, b.as_slice()).is_err() {
                return Err(ApiError("Save btf data fail".into()));
            };
        };

        let btf_path: Option<String> = if btf_data_file_path.exists() {
            Some(btf_data_file_path.as_path().display().to_string())
        } else {
            None
        };

        let empty_extra_params = vec![String::default()];

        let prog_type = match program_type.unwrap().as_str() {
            "JsonEunomia" => ProgramType::JsonEunomia,
            "Tar" => ProgramType::Tar,
            "WasmModule" => ProgramType::WasmModule,
            &_ => ProgramType::Undefine,
        };

        // assemble ProgramConfigData
        let _data = ProgramConfigData {
            url: String::default(),
            use_cache: false,
            btf_path,
            program_data_buf: Vec::from(program_data_buf.unwrap().0),
            extra_arg: extra_params
                .unwrap_or_else(|| &empty_extra_params)
                .to_owned(),
            prog_type,
            export_format_type: ExportFormatType::ExportPlantText,
        };

        // Err(ApiError("This server behavior not implemented".into()))
        Ok(StartPostResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("unimplemented".into()),
            tasks: None,
        }))
    }

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: ListGet200ResponseTasksInner,
        context: &C,
    ) -> Result<StopPostResponse, ApiError> {
        let context = context.clone();
        info!("Recieved stop command, but has not been implemented");
        info!("stop with id: {:?}", &list_get200_response_tasks_inner.id);

        info!(
            "stop_post({:?}) - X-Span-ID: {:?}",
            list_get200_response_tasks_inner,
            context.get().0.clone()
        );

        match (
            list_get200_response_tasks_inner.id,
            list_get200_response_tasks_inner.name,
        ) {
            (Some(_), _) | (_, Some(_)) => (),
            _ => eprintln!("request not contained id or name of program"),
        };

        // Err(ApiError("This server behavior not implemented".into()))
        Ok(StopPostResponse::StatusOfStoppingTheTask(
            StopPost200Response {
                status: Some("unimplemented".into()),
            },
        ))
    }
}
