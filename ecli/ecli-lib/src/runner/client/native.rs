//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Deprecated compatibility shim that adapts the legacy client API to the
//! single-session local runner.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use crate::{
    config::ProgramType,
    error::{Error, Result},
    runner::{native::NativeRunner, native::RunningProgram, ProgramHandle},
};

use super::{AbstractClient, ProgramDesc, ProgramStatus};

struct ProgramSlot {
    name: String,
    paused: bool,
    program: Arc<Mutex<Option<RunningProgram>>>,
}

struct NativeClientState {
    next_handle: ProgramHandle,
    programs: HashMap<ProgramHandle, ProgramSlot>,
}

impl Default for NativeClientState {
    fn default() -> Self {
        Self {
            next_handle: 1,
            programs: HashMap::new(),
        }
    }
}

/// Deprecated compatibility client preserved for downstream callers.
pub struct EcliNativeClient {
    state: RwLock<NativeClientState>,
}

impl Default for EcliNativeClient {
    fn default() -> Self {
        Self {
            state: RwLock::new(NativeClientState::default()),
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
        let program =
            NativeRunner::start_program(prog_buf, prog_type, export_json, args, btf_archive_path)?;

        let mut guard = self.state.write().unwrap();
        let handle = guard.next_handle;
        guard.next_handle += 1;
        guard.programs.insert(
            handle,
            ProgramSlot {
                name: name.unwrap_or_else(|| "NativeProgram".to_string()),
                paused: false,
                program: Arc::new(Mutex::new(Some(program))),
            },
        );
        Ok(handle)
    }

    async fn terminate_program(&self, handle: ProgramHandle) -> Result<()> {
        let slot = self
            .state
            .write()
            .unwrap()
            .programs
            .remove(&handle)
            .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        let mut program_guard = slot.program.lock().unwrap();
        let program = program_guard
            .take()
            .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        program.terminate()
    }

    async fn set_program_pause_state(&self, handle: ProgramHandle, pause: bool) -> Result<()> {
        let mut guard = self.state.write().unwrap();
        let slot = guard
            .programs
            .get_mut(&handle)
            .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        let mut program_guard = slot.program.lock().unwrap();
        let program = program_guard
            .as_mut()
            .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        program.set_pause(pause)?;
        slot.paused = pause;
        Ok(())
    }

    async fn fetch_logs(
        &self,
        handle: ProgramHandle,
        cursor: Option<usize>,
        maximum_count: Option<usize>,
    ) -> Result<Vec<(usize, crate::runner::LogEntry)>> {
        let program = {
            let guard = self.state.read().unwrap();
            Arc::clone(
                &guard
                    .programs
                    .get(&handle)
                    .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?
                    .program,
            )
        };
        let program_guard = program.lock().unwrap();
        let program = program_guard
            .as_ref()
            .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        Ok(program.fetch_logs(cursor, maximum_count))
    }

    async fn get_program_list(&self) -> Result<Vec<ProgramDesc>> {
        let guard = self.state.read().unwrap();
        Ok(guard
            .programs
            .iter()
            .map(|(handle, slot)| ProgramDesc {
                id: *handle,
                name: slot.name.clone(),
                status: if slot.paused {
                    ProgramStatus::Paused
                } else {
                    ProgramStatus::Running
                },
            })
            .collect())
    }
}
