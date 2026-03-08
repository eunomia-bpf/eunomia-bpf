//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Deprecated compatibility shim for the pre-issue-382 task manager API.
#![allow(deprecated)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    config::ProgramType,
    error::{Error, Result},
    runner::{
        client::{ProgramDesc, ProgramStatus},
        native::{NativeRunner, RunningProgram},
        LogEntry, ProgramHandle,
    },
};

/// The first compatibility task id.
pub const FIRST_TASK_ID: usize = 1;

/// Deprecated compatibility task manager preserved for downstream callers.
pub struct NativeTaskManager {
    next_task_id: usize,
    tasks: HashMap<usize, Arc<Mutex<Task>>>,
}

impl Default for NativeTaskManager {
    fn default() -> Self {
        Self {
            next_task_id: FIRST_TASK_ID,
            tasks: HashMap::new(),
        }
    }
}

impl NativeTaskManager {
    /// Get a reference to a compatibility task.
    pub fn get_task(&self, handle: ProgramHandle) -> Option<Arc<Mutex<Task>>> {
        self.tasks.get(&(handle as usize)).cloned()
    }

    /// Get all active compatibility tasks. Finished tasks are retained internally
    /// until explicit termination so callers can still read any tail logs after
    /// observing liveness.
    pub fn get_task_list(&mut self) -> Vec<ProgramDesc> {
        self.tasks
            .iter()
            .filter_map(|(id, task)| {
                let task = task.lock().unwrap();
                if task.has_exited() {
                    return None;
                }
                Some(ProgramDesc {
                    id: *id as ProgramHandle,
                    name: task.name.clone(),
                    status: if task.paused {
                        ProgramStatus::Paused
                    } else {
                        ProgramStatus::Running
                    },
                })
            })
            .collect()
    }

    /// Terminate a compatibility task by handle.
    pub fn terminate_task(&mut self, handle: ProgramHandle) -> Result<()> {
        let task = self
            .tasks
            .remove(&(handle as usize))
            .ok_or_else(|| Error::Bpf(format!("Invalid handle: {}", handle)))?;
        let task = match Arc::try_unwrap(task) {
            Ok(task) => task.into_inner().unwrap(),
            Err(task) => {
                self.tasks.insert(handle as usize, task);
                return Err(Error::Bpf(
                    "Some others is holding a reference to the Task, cannot terminate the program"
                        .to_string(),
                ));
            }
        };
        task.terminate()
    }

    /// Start a compatibility task.
    pub fn start_task(
        &mut self,
        name: impl Into<String>,
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> Result<usize> {
        let task_id = self.next_task_id;
        self.next_task_id += 1;
        let task = Task {
            name: name.into(),
            paused: false,
            program: Some(NativeRunner::start_program(
                prog_buf,
                prog_type,
                export_json,
                args,
                btf_archive_path,
            )?),
        };
        self.tasks.insert(task_id, Arc::new(Mutex::new(task)));
        Ok(task_id)
    }
}

/// Deprecated compatibility wrapper for a single running program.
pub struct Task {
    name: String,
    paused: bool,
    program: Option<RunningProgram>,
}

impl Task {
    fn has_exited(&self) -> bool {
        self.program
            .as_ref()
            .map(RunningProgram::has_exited)
            .unwrap_or(true)
    }

    /// Poll logs from the wrapped program.
    pub fn poll_log(&self, cursor: Option<usize>, maximum: usize) -> Vec<(usize, LogEntry)> {
        self.program
            .as_ref()
            .map(|program| program.fetch_logs(cursor, Some(maximum)))
            .unwrap_or_default()
    }

    /// Pause or resume the wrapped program.
    pub fn set_pause(&mut self, pause: bool) -> Result<()> {
        let program = self
            .program
            .as_mut()
            .ok_or_else(|| Error::Other("Task has already terminated".to_string()))?;
        program.set_pause(pause)?;
        self.paused = pause;
        Ok(())
    }

    fn terminate(mut self) -> Result<()> {
        match self.program.take() {
            Some(program) => program.terminate(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::runner::native::test_running_program_with_wasm_output;

    #[test]
    fn empty_manager_reports_no_tasks() {
        let mut manager = NativeTaskManager::default();
        assert!(manager.get_task_list().is_empty());
    }

    #[test]
    fn exited_tasks_drop_from_liveness_list_but_keep_tail_logs() {
        let task_id = FIRST_TASK_ID;
        let mut manager = NativeTaskManager::default();
        manager.next_task_id = task_id + 1;
        manager.tasks.insert(
            task_id,
            Arc::new(Mutex::new(Task {
                name: "prog".to_string(),
                paused: false,
                program: Some(test_running_program_with_wasm_output(b"out", b"err")),
            })),
        );

        for _ in 0..50 {
            if manager.get_task_list().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(manager.get_task_list().is_empty());

        let task = manager.get_task(task_id as ProgramHandle).unwrap();
        let logs = task.lock().unwrap().poll_log(None, 10);
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].1.log, "err");
        assert_eq!(logs[1].1.log, "out");
    }
}
