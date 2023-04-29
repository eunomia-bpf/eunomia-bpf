//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::sync::RwLock;

use crate::{
    config::ProgramType,
    error::{Error, Result},
    runner::{
        task_manager::NativeTaskManager, LogEntry, ProgramHandle, DEFAULT_MAXIMUM_LOG_ENTRIES,
    },
};

use super::{AbstractClient, ProgramDesc};

/// The native client
/// Run things at the local machine
pub struct EcliNativeClient {
    manager: RwLock<NativeTaskManager>,
}

impl Default for EcliNativeClient {
    fn default() -> EcliNativeClient {
        Self {
            manager: RwLock::new(NativeTaskManager::default()),
        }
    }
}

#[async_trait::async_trait]
impl AbstractClient for EcliNativeClient {
    async fn start_program(
        &self,
        name: Option<String>,
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> Result<ProgramHandle> {
        let buf = prog_buf.to_vec();
        let mut guard = self.manager.write().unwrap();
        let handle = guard.start_task(
            name.unwrap_or_else(|| "NativeProgram".to_string()),
            &buf,
            prog_type,
            export_json,
            args,
            btf_archive_path,
        )? as ProgramHandle;
        Ok(handle)
    }
    async fn terminate_program(&self, handle: ProgramHandle) -> Result<()> {
        self.manager
            .write()
            .unwrap()
            .terminate_task(handle)
            .map_err(|e| Error::Other(format!("Failed to terminate: {:?}", e)))?;
        Ok(())
    }
    async fn set_program_pause_state(&self, handle: ProgramHandle, pause: bool) -> Result<()> {
        let task_handle = {
            let guard = self.manager.read().unwrap();
            guard
                .get_task(handle)
                .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?
        };
        let mut task_guard = task_handle.lock().unwrap();
        task_guard
            .set_pause(pause)
            .map_err(|e| Error::Other(format!("Failed to set pause state: {:?}", e)))?;
        Ok(())
    }
    async fn fetch_logs(
        &self,
        handle: ProgramHandle,
        log_cursor: Option<usize>,
        maximum_count: Option<usize>,
    ) -> Result<Vec<(usize, LogEntry)>> {
        let maximum_count = maximum_count.unwrap_or(DEFAULT_MAXIMUM_LOG_ENTRIES);
        let task_handle = {
            let guard = self.manager.read().unwrap();
            guard
                .get_task(handle)
                .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?
        };
        let task_guard = task_handle.lock().unwrap();
        Ok(task_guard.poll_log(log_cursor, maximum_count))
    }
    async fn get_program_list(&self) -> Result<Vec<ProgramDesc>> {
        let mut guard = self.manager.write().unwrap();
        Ok(guard.get_task_list())
    }
}
