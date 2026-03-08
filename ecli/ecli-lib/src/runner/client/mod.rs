//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Deprecated compatibility surface for the pre-issue-382 runner API.

/// The deprecated native compatibility client.
#[cfg(feature = "native-client")]
pub mod native;

use crate::{config::ProgramType, error::Result};

use super::{LogEntry, ProgramHandle};

/// Status of an existing program in the deprecated compatibility client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramStatus {
    Running,
    Paused,
}

/// Description of an existing program in the deprecated compatibility client.
#[derive(Debug, Clone)]
pub struct ProgramDesc {
    pub id: ProgramHandle,
    pub name: String,
    pub status: ProgramStatus,
}

/// Deprecated client interface preserved for downstream compatibility.
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

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn compatibility_types_are_available_without_native_feature() {
        let handle: ProgramHandle = 7;
        let desc = ProgramDesc {
            id: handle,
            name: "prog".to_string(),
            status: ProgramStatus::Running,
        };

        assert_eq!(desc.id, 7);
        assert_eq!(desc.name, "prog");
        assert!(matches!(desc.status, ProgramStatus::Running));
    }
}
