use crate::runner::models::*;
use serde::{Deserialize, Serialize};

/// ListGetResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ListGetResponse {
    /// List of running tasks
    ListOfRunningTasks(ListGet200Response),
}
/// pub enum LogPostResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum LogPostResponse {
    /// send log
    SendLog(LogPost200Response),
}
/// pub enum StartPostResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum StartPostResponse {
    /// List of running tasks
    ListOfRunningTasks(ListGet200Response),
}

/// pub enum StopPostResponse
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum StopPostResponse {
    /// Status of stopping the task
    StatusOfStoppingTheTask(StopPost200Response),
}
