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
    runner::{native::NativeRunner, native::RunningProgram, LogEntry, ProgramHandle},
};

use super::{AbstractClient, ProgramDesc, ProgramStatus};

struct ProgramSlot {
    name: String,
    paused: bool,
    program: Arc<Mutex<Option<RunningProgram>>>,
}

struct CompletedProgram {
    logs: Vec<(usize, LogEntry)>,
}

struct NativeClientState {
    next_handle: ProgramHandle,
    programs: HashMap<ProgramHandle, ProgramSlot>,
    completed_programs: HashMap<ProgramHandle, CompletedProgram>,
}

impl Default for NativeClientState {
    fn default() -> Self {
        Self {
            next_handle: 1,
            programs: HashMap::new(),
            completed_programs: HashMap::new(),
        }
    }
}

impl NativeClientState {
    fn retire_exited_programs(&mut self) {
        let completed_handles = self
            .programs
            .iter()
            .filter_map(|(handle, slot)| {
                let program_guard = slot.program.lock().unwrap();
                let program = program_guard.as_ref()?;
                if !program.has_exited() {
                    return None;
                }
                Some((*handle, program.fetch_logs(None, Some(usize::MAX))))
            })
            .collect::<Vec<_>>();

        for (handle, logs) in completed_handles {
            self.programs.remove(&handle);
            self.completed_programs
                .insert(handle, CompletedProgram { logs });
        }
    }
}

fn snapshot_logs(
    logs: &[(usize, LogEntry)],
    cursor: Option<usize>,
    maximum_count: Option<usize>,
) -> Vec<(usize, LogEntry)> {
    logs.iter()
        .filter(|(log_cursor, _)| cursor.map_or(true, |cursor| *log_cursor >= cursor))
        .take(maximum_count.unwrap_or(crate::runner::DEFAULT_MAXIMUM_LOG_ENTRIES))
        .cloned()
        .collect()
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
        let slot = {
            let mut guard = self.state.write().unwrap();
            if let Some(slot) = guard.programs.remove(&handle) {
                slot
            } else if guard.completed_programs.remove(&handle).is_some() {
                return Ok(());
            } else {
                return Err(Error::Other(format!("Invalid handle: {}", handle)));
            }
        };
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
        let completed_logs = {
            let guard = self.state.read().unwrap();
            if let Some(slot) = guard.programs.get(&handle) {
                Some(Arc::clone(&slot.program))
            } else if let Some(program) = guard.completed_programs.get(&handle) {
                return Ok(snapshot_logs(&program.logs, cursor, maximum_count));
            } else {
                None
            }
        };
        let program =
            completed_logs.ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        let program_guard = program.lock().unwrap();
        let program = program_guard
            .as_ref()
            .ok_or_else(|| Error::Other(format!("Invalid handle: {}", handle)))?;
        Ok(program.fetch_logs(cursor, maximum_count))
    }

    async fn get_program_list(&self) -> Result<Vec<ProgramDesc>> {
        let mut guard = self.state.write().unwrap();
        // Retain completed handles until explicit cleanup so one finished session
        // is not dropped while callers keep polling list state for another.
        guard.retire_exited_programs();
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

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::runner::native::{
        test_running_program_with_delayed_wasm_output, test_running_program_with_wasm_output,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn completed_programs_keep_tail_logs_while_other_programs_are_still_running() {
        let client = EcliNativeClient::default();
        let completed_handle = 1;
        let active_handle = 2;
        let mut state = client.state.write().unwrap();
        state.programs.insert(
            completed_handle,
            ProgramSlot {
                name: "completed".to_string(),
                paused: false,
                program: Arc::new(Mutex::new(Some(test_running_program_with_wasm_output(
                    b"out", b"err",
                )))),
            },
        );
        state.programs.insert(
            active_handle,
            ProgramSlot {
                name: "active".to_string(),
                paused: false,
                program: Arc::new(Mutex::new(Some(
                    test_running_program_with_delayed_wasm_output(
                        std::time::Duration::from_millis(250),
                        b"",
                        b"",
                    ),
                ))),
            },
        );
        drop(state);

        let mut list_only_shows_active_handle = false;
        for _ in 0..50 {
            let list = client.get_program_list().await.unwrap();
            if list.len() == 1 && list[0].id == active_handle {
                list_only_shows_active_handle = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(list_only_shows_active_handle);

        for _ in 0..3 {
            let list = client.get_program_list().await.unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].id, active_handle);

            let logs = client
                .fetch_logs(completed_handle, None, Some(10))
                .await
                .unwrap();
            assert_eq!(logs.len(), 2);
            assert_eq!(logs[0].1.log, "err");
            assert_eq!(logs[1].1.log, "out");
        }

        client.terminate_program(completed_handle).await.unwrap();
        assert!(client
            .fetch_logs(completed_handle, None, Some(10))
            .await
            .is_err());
        client.terminate_program(active_handle).await.unwrap();

        let state = client.state.read().unwrap();
        assert!(state.programs.is_empty());
        assert!(state.completed_programs.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn quiet_completed_programs_are_retained_until_explicit_cleanup() {
        let client = EcliNativeClient::default();
        let handle = 1;
        client.state.write().unwrap().programs.insert(
            handle,
            ProgramSlot {
                name: "quiet".to_string(),
                paused: false,
                program: Arc::new(Mutex::new(Some(test_running_program_with_wasm_output(
                    b"", b"",
                )))),
            },
        );

        let mut list_became_empty = false;
        for _ in 0..50 {
            if client.get_program_list().await.unwrap().is_empty() {
                list_became_empty = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(list_became_empty);
        assert!(client
            .fetch_logs(handle, None, Some(10))
            .await
            .unwrap()
            .is_empty());
        assert!(client.get_program_list().await.unwrap().is_empty());
        assert!(client
            .fetch_logs(handle, None, Some(10))
            .await
            .unwrap()
            .is_empty());

        client.terminate_program(handle).await.unwrap();
        assert!(client.fetch_logs(handle, None, Some(10)).await.is_err());

        let state = client.state.read().unwrap();
        assert!(state.programs.is_empty());
        assert!(state.completed_programs.is_empty());
    }
}
