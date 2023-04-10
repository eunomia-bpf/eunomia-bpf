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

/// ListGetResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ListGetResponse {
    /// List of running tasks
    ListOfRunningTasks(models::ListGet200Response),
}
/// pub enum LogPostResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum LogPostResponse {
    /// send log
    SendLog(models::LogPost200Response),
}
/// pub enum StartPostResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum StartPostResponse {
    /// List of running tasks
    ListOfRunningTasks(models::ListGet200Response),
}

/// pub enum StopPostResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum StopPostResponse {
    /// Status of stopping the task
    StatusOfStoppingTheTask(models::StopPost200Response),
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
    async fn list_get(&self, context: &C) -> Result<ListGetResponse, ApiError>;

    /// get log
    async fn log_post(
        &self,
        log_post_request: models::LogPostRequest,
        context: &C,
    ) -> Result<LogPostResponse, ApiError>;

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        program_name: Option<String>,
        btf_data: Option<swagger::ByteArray>,
        extra_params: Option<&Vec<String>>,
        context: &C,
    ) -> Result<StartPostResponse, ApiError>;

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: models::ListGet200ResponseTasksInner,
        context: &C,
    ) -> Result<StopPostResponse, ApiError>;
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
    async fn list_get(&self) -> Result<ListGetResponse, ApiError>;

    /// get log
    async fn log_post(
        &self,
        log_post_request: models::LogPostRequest,
    ) -> Result<LogPostResponse, ApiError>;

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        program_name: Option<String>,
        btf_data: Option<swagger::ByteArray>,
        extra_params: Option<&Vec<String>>,
    ) -> Result<StartPostResponse, ApiError>;

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: models::ListGet200ResponseTasksInner,
    ) -> Result<StopPostResponse, ApiError>;
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
    async fn list_get(&self) -> Result<ListGetResponse, ApiError> {
        let context = self.context().clone();
        self.api().list_get(&context).await
    }

    /// get log
    async fn log_post(
        &self,
        log_post_request: models::LogPostRequest,
    ) -> Result<LogPostResponse, ApiError> {
        let context = self.context().clone();
        self.api().log_post(log_post_request, &context).await
    }

    /// Start a new task
    async fn start_post(
        &self,
        program_data_buf: Option<swagger::ByteArray>,
        program_type: Option<String>,
        program_name: Option<String>,
        btf_data: Option<swagger::ByteArray>,
        extra_params: Option<&Vec<String>>,
    ) -> Result<StartPostResponse, ApiError> {
        let context = self.context().clone();
        self.api()
            .start_post(
                program_data_buf,
                program_type,
                program_name,
                btf_data,
                extra_params,
                &context,
            )
            .await
    }

    /// Stop a task by id or name
    async fn stop_post(
        &self,
        list_get200_response_tasks_inner: models::ListGet200ResponseTasksInner,
    ) -> Result<StopPostResponse, ApiError> {
        let context = self.context().clone();
        self.api()
            .stop_post(list_get200_response_tasks_inner, &context)
            .await
    }
}

#[cfg(feature = "client")]
pub mod client;

// Re-export Client as a top-level name
#[cfg(feature = "client")]
pub use client::Client;

/// server module
#[cfg(feature = "server")]
pub mod server;

// Re-export router() as a top-level name
#[cfg(feature = "server")]
pub use self::server::Service;

/// context for ecli server api
#[cfg(feature = "server")]
pub mod context;

/// models of ecli server api
pub mod models;

#[cfg(any(feature = "client", feature = "server"))]
pub(crate) mod header;
