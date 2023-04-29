#![allow(
    missing_docs,
    trivial_casts,
    unused_variables,
    unused_mut,
    unused_imports,
    unused_extern_crates,
    non_camel_case_types
)]
#![allow(unused_imports, unused_attributes)]
#![allow(clippy::derive_partial_eq_without_eq, clippy::blacklisted_name)]

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::task::{Context, Poll};
use swagger::{ApiError, ContextWrapper};

type ServiceError = Box<dyn Error + Send + Sync + 'static>;

pub const BASE_PATH: &str = "";
pub const API_VERSION: &str = "1.0.0";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum GetTaskListResponse {
    /// List of running tasks
    ListOfRunningTasks(models::TaskListResponse),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum GetTaskLogByIdResponse {
    /// Invalid handle
    InvalidHandle(models::GeneralError),
    /// The log fetched
    TheLogFetched(Vec<models::GetTaskLogResponseInner>),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum PauseTaskByIdResponse {
    /// Failed to pause
    FailedToPause(models::GeneralError),
    /// Invalid handle
    InvalidHandle(models::GeneralError),
    /// Status of pausing the task
    StatusOfPausingTheTask(models::TaskStatus),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum ResumeTaskByIdResponse {
    /// Failed to resume
    FailedToResume(models::GeneralError),
    /// Invalid handle
    InvalidHandle(models::GeneralError),
    /// Status of the task
    StatusOfTheTask(models::TaskStatus),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum StartTaskResponse {
    /// Invalid arguments
    InvalidArguments(models::GeneralError),
    /// List of running tasks
    ListOfRunningTasks(models::StartTask200Response),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
pub enum StopTaskByIdResponse {
    /// Status of stopping the task
    StatusOfStoppingTheTask(serde_json::Value),
    /// Invalid handle
    InvalidHandle(models::GeneralError),
    /// Failed to terminate
    FailedToTerminate(models::GeneralError),
}

/// API
#[async_trait]
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
pub trait Api<C: Send + Sync> {
    fn poll_ready(
        &self,
        _cx: &mut Context,
    ) -> Poll<Result<(), Box<dyn Error + Send + Sync + 'static>>> {
        Poll::Ready(Ok(()))
    }

    /// Get list of running tasks
    async fn get_task_list(&self, context: &C) -> Result<GetTaskListResponse, ApiError>;

    /// get log
    async fn get_task_log_by_id(
        &self,
        get_task_log_request: models::GetTaskLogRequest,
        context: &C,
    ) -> Result<GetTaskLogByIdResponse, ApiError>;

    /// Pause a task by id
    async fn pause_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &C,
    ) -> Result<PauseTaskByIdResponse, ApiError>;

    /// Resume a task by id
    async fn resume_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &C,
    ) -> Result<ResumeTaskByIdResponse, ApiError>;

    /// Start a new task
    async fn start_task(
        &self,
        start_task_request: models::StartTaskRequest,
        context: &C,
    ) -> Result<StartTaskResponse, ApiError>;

    /// Stop a task by id
    async fn stop_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
        context: &C,
    ) -> Result<StopTaskByIdResponse, ApiError>;
}

/// API where `Context` isn't passed on every API call
#[async_trait]
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
pub trait ApiNoContext<C: Send + Sync> {
    fn poll_ready(
        &self,
        _cx: &mut Context,
    ) -> Poll<Result<(), Box<dyn Error + Send + Sync + 'static>>>;

    fn context(&self) -> &C;

    /// Get list of running tasks
    async fn get_task_list(&self) -> Result<GetTaskListResponse, ApiError>;

    /// get log
    async fn get_task_log_by_id(
        &self,
        get_task_log_request: models::GetTaskLogRequest,
    ) -> Result<GetTaskLogByIdResponse, ApiError>;

    /// Pause a task by id
    async fn pause_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
    ) -> Result<PauseTaskByIdResponse, ApiError>;

    /// Resume a task by id
    async fn resume_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
    ) -> Result<ResumeTaskByIdResponse, ApiError>;

    /// Start a new task
    async fn start_task(
        &self,
        start_task_request: models::StartTaskRequest,
    ) -> Result<StartTaskResponse, ApiError>;

    /// Stop a task by id
    async fn stop_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
    ) -> Result<StopTaskByIdResponse, ApiError>;
}

/// Trait to extend an API to make it easy to bind it to a context.
pub trait ContextWrapperExt<C: Send + Sync>
where
    Self: Sized,
{
    /// Binds this API to a context.
    fn with_context(self, context: C) -> ContextWrapper<Self, C>;
}

impl<T: Api<C> + Send + Sync, C: Clone + Send + Sync> ContextWrapperExt<C> for T {
    fn with_context(self: T, context: C) -> ContextWrapper<T, C> {
        ContextWrapper::<T, C>::new(self, context)
    }
}

#[async_trait]
impl<T: Api<C> + Send + Sync, C: Clone + Send + Sync> ApiNoContext<C> for ContextWrapper<T, C> {
    fn poll_ready(&self, cx: &mut Context) -> Poll<Result<(), ServiceError>> {
        self.api().poll_ready(cx)
    }

    fn context(&self) -> &C {
        ContextWrapper::context(self)
    }

    /// Get list of running tasks
    async fn get_task_list(&self) -> Result<GetTaskListResponse, ApiError> {
        let context = self.context().clone();
        self.api().get_task_list(&context).await
    }

    /// get log
    async fn get_task_log_by_id(
        &self,
        get_task_log_request: models::GetTaskLogRequest,
    ) -> Result<GetTaskLogByIdResponse, ApiError> {
        let context = self.context().clone();
        self.api()
            .get_task_log_by_id(get_task_log_request, &context)
            .await
    }

    /// Pause a task by id
    async fn pause_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
    ) -> Result<PauseTaskByIdResponse, ApiError> {
        let context = self.context().clone();
        self.api()
            .pause_task_by_id(simple_id_request, &context)
            .await
    }

    /// Resume a task by id
    async fn resume_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
    ) -> Result<ResumeTaskByIdResponse, ApiError> {
        let context = self.context().clone();
        self.api()
            .resume_task_by_id(simple_id_request, &context)
            .await
    }

    /// Start a new task
    async fn start_task(
        &self,
        start_task_request: models::StartTaskRequest,
    ) -> Result<StartTaskResponse, ApiError> {
        let context = self.context().clone();
        self.api().start_task(start_task_request, &context).await
    }

    /// Stop a task by id
    async fn stop_task_by_id(
        &self,
        simple_id_request: models::SimpleIdRequest,
    ) -> Result<StopTaskByIdResponse, ApiError> {
        let context = self.context().clone();
        self.api()
            .stop_task_by_id(simple_id_request, &context)
            .await
    }
}

#[cfg(feature = "client")]
pub mod client;

// Re-export Client as a top-level name
#[cfg(feature = "client")]
pub use client::Client;

#[cfg(feature = "server")]
pub mod server;

// Re-export router() as a top-level name
#[cfg(feature = "server")]
pub use self::server::Service;

#[cfg(feature = "server")]
pub mod context;

pub mod models;

#[cfg(any(feature = "client", feature = "server"))]
pub(crate) mod header;
