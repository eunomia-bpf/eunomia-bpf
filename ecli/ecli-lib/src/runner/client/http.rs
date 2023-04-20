//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use base64::Engine;
use ecli_server_codegen::{
    client::HyperClient,
    models::{GeneralError, GetTaskLogRequest, SimpleIdRequest, StartTaskRequest},
    ApiNoContext, Client, ContextWrapperExt, GetTaskListResponse, GetTaskLogByIdResponse,
    PauseTaskByIdResponse, ResumeTaskByIdResponse, StartTaskResponse, StopTaskByIdResponse,
};
use swagger::{ContextBuilder, ContextWrapper, DropContextService, EmptyContext, XSpanIdString};

use crate::{
    config::ProgramType,
    error::{Error, Result},
    runner::{client::ProgramStatus, LogEntry, LogType, ProgramHandle},
};
use swagger::Push;

use super::{AbstractClient, ProgramDesc};

type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, XSpanIdString);
type ClientType = ContextWrapper<
    Client<
        DropContextService<HyperClient, ContextBuilder<XSpanIdString, EmptyContext>>,
        ContextBuilder<XSpanIdString, EmptyContext>,
    >,
    ContextBuilder<XSpanIdString, EmptyContext>,
>;
/// The HTTP Client
pub struct EcliHttpClient {
    client: ClientType,
}

impl EcliHttpClient {
    /// Create a http client with the provided endpoint
    pub fn new(url: impl AsRef<str>) -> Result<Self> {
        let url = url.as_ref().to_string();
        let context: ClientContext =
            swagger::make_context!(ContextBuilder, EmptyContext, XSpanIdString::default());
        let client = Client::try_new(url.as_str())
            .map_err(|e| Error::Http(format!("Failed to create client: {}", e)))?
            .with_context(context);
        Ok(Self { client })
    }
}
#[async_trait::async_trait]
impl AbstractClient for EcliHttpClient {
    async fn start_program(
        &self,
        name: Option<String>,
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> crate::error::Result<crate::runner::ProgramHandle> {
        let file_contents = prog_buf.to_vec();
        let b64 = tokio::task::spawn_blocking(move || {
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(file_contents)
        })
        .await
        .map_err(|e| Error::Other(format!("Failed to join: {}", e)))?;
        use ecli_server_codegen::models::ProgramType;
        let ret = self
            .client
            .start_task(StartTaskRequest {
                btf_archive_path,
                program_name: name,
                export_json: Some(export_json),
                extra_args: Some(args.to_vec()),
                program_data_buf: b64,
                program_type: match prog_type {
                    crate::config::ProgramType::JsonEunomia => ProgramType::Json,
                    crate::config::ProgramType::WasmModule => ProgramType::Wasm,
                    crate::config::ProgramType::Tar => ProgramType::Tar,
                },
            })
            .await
            .map_err(|e| Error::Http(format!("Failed to run start task: {:?}", e)))?;

        Ok(match ret {
            StartTaskResponse::ListOfRunningTasks(v) => v.id,
            StartTaskResponse::InvalidArguments(GeneralError { message }) => {
                return Err(Error::Bpf(message))
            }
        })
    }

    async fn terminate_program(
        &self,
        handle: crate::runner::ProgramHandle,
    ) -> crate::error::Result<()> {
        match self
            .client
            .stop_task_by_id(SimpleIdRequest { id: handle })
            .await
            .map_err(|e| Error::Http(format!("Failed to stop program: {:?}", e)))?
        {
            StopTaskByIdResponse::StatusOfStoppingTheTask(_) => Ok(()),
            StopTaskByIdResponse::FailedToTerminate(GeneralError { message }) => {
                Err(Error::Bpf(message))
            }
            StopTaskByIdResponse::InvalidHandle(GeneralError { message }) => {
                Err(Error::InvalidParam(message))
            }
        }
    }

    async fn set_program_pause_state(
        &self,
        handle: crate::runner::ProgramHandle,
        pause: bool,
    ) -> crate::error::Result<()> {
        let req = SimpleIdRequest { id: handle };
        if pause {
            match self
                .client
                .pause_task_by_id(req)
                .await
                .map_err(|e| Error::Http(format!("Failed to pause program: {:?}", e)))?
            {
                PauseTaskByIdResponse::FailedToPause(GeneralError { message }) => {
                    Err(Error::Bpf(message))
                }
                PauseTaskByIdResponse::InvalidHandle(GeneralError { message }) => {
                    Err(Error::InvalidParam(message))
                }
                PauseTaskByIdResponse::StatusOfPausingTheTask(_) => Ok(()),
            }
        } else {
            match self
                .client
                .resume_task_by_id(req)
                .await
                .map_err(|e| Error::Http(format!("Failed to resume program: {:?}", e)))?
            {
                ResumeTaskByIdResponse::FailedToResume(GeneralError { message }) => {
                    Err(Error::Bpf(message))
                }
                ResumeTaskByIdResponse::InvalidHandle(GeneralError { message }) => {
                    Err(Error::InvalidParam(message))
                }
                ResumeTaskByIdResponse::StatusOfTheTask(_) => Ok(()),
            }
        }
    }

    async fn fetch_logs(
        &self,
        handle: ProgramHandle,
        log_cursor: Option<usize>,
        maximum_count: Option<usize>,
    ) -> crate::error::Result<Vec<(usize, LogEntry)>> {
        let req = GetTaskLogRequest {
            id: handle,
            maximum_count: maximum_count.map(|v| v as u64),
            log_cursor: log_cursor.map(|v| v as u64),
        };
        let resp = self
            .client
            .get_task_log_by_id(req)
            .await
            .map_err(|e| Error::Http(format!("Failed to get logs: {:?}", e)))?;
        let resp = match resp {
            GetTaskLogByIdResponse::InvalidHandle(GeneralError { message }) => {
                return Err(Error::Bpf(message))
            }
            GetTaskLogByIdResponse::TheLogFetched(v) => v,
        };
        use ecli_server_codegen::models::LogType as HttpLogType;
        Ok(resp
            .into_iter()
            .map(|v| {
                (
                    v.cursor as usize,
                    LogEntry {
                        log: v.log.log,
                        log_type: match v.log.log_type {
                            HttpLogType::Stderr => LogType::Stderr,
                            HttpLogType::Stdout => LogType::Stdout,
                            HttpLogType::Plain => LogType::Plain,
                        },
                        timestamp: v.log.timestamp,
                    },
                )
            })
            .collect())
    }
    async fn get_program_list(&self) -> Result<Vec<ProgramDesc>> {
        let ret = self
            .client
            .get_task_list()
            .await
            .map_err(|e| Error::Http(format!("Failed to get task list: {:?}", e)))?;
        let GetTaskListResponse::ListOfRunningTasks(ret) = ret;
        use ecli_server_codegen::models::TaskStatus as HttpTaskStatus;
        Ok(ret
            .tasks
            .into_iter()
            .map(|v| ProgramDesc {
                id: v.id as ProgramHandle,
                name: v.name,
                status: match v.status {
                    HttpTaskStatus::Running => ProgramStatus::Running,
                    HttpTaskStatus::Paused => ProgramStatus::Paused,
                },
            })
            .collect())
    }
}
