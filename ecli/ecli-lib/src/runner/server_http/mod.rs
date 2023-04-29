//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::sync::{Arc, RwLock};

use base64::Engine;
use ecli_server_codegen::{
    models::{
        self, GeneralError, GetTaskLogResponseInner, GetTaskLogResponseInnerLog, TaskListResponse,
        TaskListResponseTasksInner,
    },
    Api, GetTaskListResponse, GetTaskLogByIdResponse, PauseTaskByIdResponse,
    ResumeTaskByIdResponse, StartTaskResponse, StopTaskByIdResponse,
};
use serde_json::json;
use swagger::{ApiError, Has, XSpanIdString};

use crate::{config::ProgramType, runner::DEFAULT_MAXIMUM_LOG_ENTRIES};

use super::{client::ProgramStatus, task_manager::NativeTaskManager, LogType};
/// The AppState
#[derive(Clone)]
pub struct HttpServerState {
    task_manager: Arc<RwLock<NativeTaskManager>>,
    span_id: XSpanIdString,
}
impl Default for HttpServerState {
    fn default() -> HttpServerState {
        Self {
            task_manager: Arc::new(RwLock::new(NativeTaskManager::default())),
            span_id: XSpanIdString::default(),
        }
    }
}

impl Has<XSpanIdString> for HttpServerState {
    fn get(&self) -> &XSpanIdString {
        &self.span_id
    }

    fn get_mut(&mut self) -> &mut XSpanIdString {
        &mut self.span_id
    }

    fn set(&mut self, value: XSpanIdString) {
        self.span_id = value;
    }
}

/// The server api implementations
#[derive(Clone)]
pub struct EcliHttpServerAPI;
#[async_trait::async_trait]
impl Api<HttpServerState> for EcliHttpServerAPI {
    /// Get list of running tasks
    async fn get_task_list(
        &self,
        context: &HttpServerState,
    ) -> Result<GetTaskListResponse, ApiError> {
        let mut guard = context.task_manager.write().unwrap();
        let task_list = guard
            .get_task_list()
            .into_iter()
            .map(|v| TaskListResponseTasksInner {
                id: v.id,
                name: v.name,
                status: match v.status {
                    super::client::ProgramStatus::Running => models::TaskStatus::Running,
                    super::client::ProgramStatus::Paused => models::TaskStatus::Paused,
                },
            })
            .collect();
        Ok(GetTaskListResponse::ListOfRunningTasks(
            models::TaskListResponse { tasks: task_list },
        ))
    }

    /// get logs
    async fn get_task_log_by_id(
        &self,
        get_task_log_request: models::GetTaskLogRequest,
        context: &HttpServerState,
    ) -> Result<GetTaskLogByIdResponse, ApiError> {
        let models::GetTaskLogRequest {
            id,
            log_cursor,
            maximum_count,
        } = get_task_log_request;

        let logs = {
            let task = if let Some(v) = context.task_manager.read().unwrap().get_task(id) {
                v
            } else {
                return Ok(GetTaskLogByIdResponse::InvalidHandle(GeneralError {
                    message: format!("Invalid handle: {}", id),
                }));
            };
            let task_guard = task.lock().unwrap();
            task_guard.poll_log(
                log_cursor.map(|v| v as usize),
                maximum_count
                    .map(|v| v as usize)
                    .unwrap_or(DEFAULT_MAXIMUM_LOG_ENTRIES),
            )
        };
        use ecli_server_codegen::models::LogType as HttpLogType;
        Ok(GetTaskLogByIdResponse::TheLogFetched(
            logs.into_iter()
                .map(|v| GetTaskLogResponseInner {
                    cursor: v.0 as u64,
                    log: GetTaskLogResponseInnerLog {
                        log: v.1.log,
                        timestamp: v.1.timestamp,
                        log_type: match v.1.log_type {
                            LogType::Plain => HttpLogType::Plain,
                            LogType::Stderr => HttpLogType::Stderr,
                            LogType::Stdout => HttpLogType::Stdout,
                        },
                    },
                })
                .collect(),
        ))
    }

    /// Pause a task by id
    async fn pause_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &HttpServerState,
    ) -> Result<PauseTaskByIdResponse, ApiError> {
        let id = simple_id_request.id;

        let task = if let Some(v) = context.task_manager.read().unwrap().get_task(id) {
            v
        } else {
            return Ok(PauseTaskByIdResponse::InvalidHandle(GeneralError {
                message: format!("Invalid handle: {}", id),
            }));
        };
        let mut task_guard = task.lock().unwrap();
        if let Err(e) = task_guard.set_pause(true) {
            return Ok(PauseTaskByIdResponse::FailedToPause(GeneralError {
                message: format!("Failed to pause: {}", e),
            }));
        }

        Ok(PauseTaskByIdResponse::StatusOfPausingTheTask(
            models::TaskStatus::Paused,
        ))
    }

    /// Resume a task by id
    async fn resume_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &HttpServerState,
    ) -> Result<ResumeTaskByIdResponse, ApiError> {
        let id = simple_id_request.id;

        let task = if let Some(v) = context.task_manager.read().unwrap().get_task(id) {
            v
        } else {
            return Ok(ResumeTaskByIdResponse::InvalidHandle(GeneralError {
                message: format!("Invalid handle: {}", id),
            }));
        };
        let mut task_guard = task.lock().unwrap();
        if let Err(e) = task_guard.set_pause(false) {
            return Ok(ResumeTaskByIdResponse::FailedToResume(GeneralError {
                message: format!("Failed to resume: {}", e),
            }));
        }

        Ok(ResumeTaskByIdResponse::StatusOfTheTask(
            models::TaskStatus::Running,
        ))
    }

    /// Start a new task
    async fn start_task(
        &self,
        start_task_request: models::StartTaskRequest,
        context: &HttpServerState,
    ) -> Result<StartTaskResponse, ApiError> {
        let models::StartTaskRequest {
            program_data_buf,
            program_type,
            program_name,
            btf_archive_path,
            extra_args,
            export_json,
        } = start_task_request;
        let program_name = program_name
            .unwrap_or_else(|| format!("bpf-program-{}", chrono::Local::now().timestamp()));
        let extra_args = extra_args.unwrap_or_default();
        let export_json = export_json.unwrap_or(false);

        let buf = match tokio::task::spawn_blocking(move || {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(program_data_buf)
        })
        .await
        .map_err(|e| ApiError(format!("Failed to await blocking task: {}", e)))?
        {
            Ok(v) => v,
            Err(e) => {
                return Ok(StartTaskResponse::InvalidArguments(GeneralError {
                    message: format!("Invalid base64: {}", e),
                }));
            }
        };

        let mut guard = context.task_manager.write().unwrap();
        use ecli_server_codegen::models::ProgramType as HttpProgramType;
        let handle = match guard.start_task(
            program_name,
            &buf,
            match program_type {
                HttpProgramType::Json => ProgramType::JsonEunomia,
                HttpProgramType::Wasm => ProgramType::WasmModule,
                HttpProgramType::Tar => ProgramType::Tar,
            },
            export_json,
            &extra_args,
            btf_archive_path,
        ) {
            Ok(v) => v,
            Err(e) => {
                return Ok(StartTaskResponse::InvalidArguments(GeneralError {
                    message: format!("Failed to start task: {}", e),
                }));
            }
        };
        let running_tasks = guard.get_task_list();
        use ecli_server_codegen::models::TaskStatus as HttpTaskStatus;
        Ok(StartTaskResponse::ListOfRunningTasks(
            models::StartTask200Response {
                id: handle as u64,
                task_list: TaskListResponse {
                    tasks: running_tasks
                        .into_iter()
                        .map(|v| TaskListResponseTasksInner {
                            status: match v.status {
                                ProgramStatus::Paused => HttpTaskStatus::Paused,
                                ProgramStatus::Running => HttpTaskStatus::Running,
                            },
                            id: v.id,
                            name: v.name,
                        })
                        .collect(),
                },
            },
        ))
    }

    /// Stop a task by id
    async fn stop_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &HttpServerState,
    ) -> Result<StopTaskByIdResponse, ApiError> {
        let id = simple_id_request.id;
        log::info!("Stopping task: {}", id);

        if context.task_manager.read().unwrap().get_task(id).is_none() {
            return Ok(StopTaskByIdResponse::InvalidHandle(GeneralError {
                message: format!("Invalid handle: {}", id),
            }));
        }

        if let Err(e) = context.task_manager.write().unwrap().terminate_task(id) {
            return Ok(StopTaskByIdResponse::FailedToTerminate(GeneralError {
                message: format!("Failed to terminate: {}", e),
            }));
        }
        Ok(StopTaskByIdResponse::StatusOfStoppingTheTask(json!({})))
    }
}
