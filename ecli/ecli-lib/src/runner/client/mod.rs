//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

/// The HTTP client
#[cfg(feature = "http-client")]
pub mod http;
/// The native client
#[cfg(feature = "native-client")]
pub mod native;

use crate::{config::ProgramType, error::Result};

use super::{LogEntry, ProgramHandle};

/// Status of an exist program
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramStatus {
    Running,
    Paused,
}
/// Description of an exist program
#[derive(Debug, Clone)]
pub struct ProgramDesc {
    pub id: ProgramHandle,
    pub name: String,
    pub status: ProgramStatus,
}
/// Common interfaces for client
#[async_trait::async_trait]
pub trait AbstractClient {
    async fn start_program(
        &self,
        name: Option<String>,
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> Result<ProgramHandle>;
    async fn terminate_program(&self, handle: ProgramHandle) -> Result<()>;
    async fn set_program_pause_state(&self, handle: ProgramHandle, pause: bool) -> Result<()>;
    async fn fetch_logs(
        &self,
        handle: ProgramHandle,
        cursor: Option<usize>,
        maximum_count: Option<usize>,
    ) -> Result<Vec<(usize, LogEntry)>>;
    async fn get_program_list(&self) -> Result<Vec<ProgramDesc>>;
}
