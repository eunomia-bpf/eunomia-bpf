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
    completed_tasks: HashMap<usize, CompletedTask>,
}

impl Default for NativeTaskManager {
    fn default() -> Self {
        Self {
            next_task_id: FIRST_TASK_ID,
            tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
        }
    }
}

impl NativeTaskManager {
    fn retire_exited_tasks(&mut self) {
        self.completed_tasks.clear();

        let completed_ids = self
            .tasks
            .iter()
            .filter_map(|(id, task)| {
                let task = task.lock().unwrap();
                if !task.has_exited() {
                    return None;
                }
                Some((*id, task.completed_snapshot()))
            })
            .collect::<Vec<_>>();

        for (id, completed_task) in completed_ids {
            self.tasks.remove(&id);
            if !completed_task.logs.is_empty() {
                self.completed_tasks.insert(id, completed_task);
            }
        }
    }

    /// Get a reference to a compatibility task.
    pub fn get_task(&self, handle: ProgramHandle) -> Option<Arc<Mutex<Task>>> {
        self.tasks.get(&(handle as usize)).cloned().or_else(|| {
            self.completed_tasks
                .get(&(handle as usize))
                .map(|task| Arc::new(Mutex::new(Task::from_completed(task))))
        })
    }

    /// Get all active compatibility tasks. Finished tasks are retained for one
    /// additional liveness poll so callers can still read any tail logs after
    /// observing liveness.
    pub fn get_task_list(&mut self) -> Vec<ProgramDesc> {
        self.retire_exited_tasks();
        self.tasks
            .iter()
            .map(|(id, task)| {
                let task = task.lock().unwrap();
                ProgramDesc {
                    id: *id as ProgramHandle,
                    name: task.name.clone(),
                    status: if task.paused {
                        ProgramStatus::Paused
                    } else {
                        ProgramStatus::Running
                    },
                }
            })
            .collect()
    }

    /// Terminate a compatibility task by handle.
    pub fn terminate_task(&mut self, handle: ProgramHandle) -> Result<()> {
        let task = if let Some(task) = self.tasks.remove(&(handle as usize)) {
            task
        } else if self.completed_tasks.remove(&(handle as usize)).is_some() {
            return Ok(());
        } else {
            return Err(Error::Bpf(format!("Invalid handle: {}", handle)));
        };
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
            completed_logs: None,
        };
        self.tasks.insert(task_id, Arc::new(Mutex::new(task)));
        Ok(task_id)
    }
}

struct CompletedTask {
    name: String,
    logs: Vec<(usize, LogEntry)>,
}

/// Deprecated compatibility wrapper for a single running program.
pub struct Task {
    name: String,
    paused: bool,
    program: Option<RunningProgram>,
    completed_logs: Option<Vec<(usize, LogEntry)>>,
}

impl Task {
    fn has_exited(&self) -> bool {
        self.program
            .as_ref()
            .map(RunningProgram::has_exited)
            .unwrap_or(true)
    }

    fn completed_snapshot(&self) -> CompletedTask {
        CompletedTask {
            name: self.name.clone(),
            logs: self
                .program
                .as_ref()
                .map(|program| program.fetch_logs(None, Some(usize::MAX)))
                .unwrap_or_else(|| self.completed_logs.clone().unwrap_or_default()),
        }
    }

    fn from_completed(task: &CompletedTask) -> Self {
        Self {
            name: task.name.clone(),
            paused: false,
            program: None,
            completed_logs: Some(task.logs.clone()),
        }
    }

    /// Poll logs from the wrapped program.
    pub fn poll_log(&self, cursor: Option<usize>, maximum: usize) -> Vec<(usize, LogEntry)> {
        if let Some(program) = self.program.as_ref() {
            return program.fetch_logs(cursor, Some(maximum));
        }

        self.completed_logs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|(log_cursor, _)| cursor.map_or(true, |cursor| *log_cursor >= cursor))
            .take(maximum)
            .cloned()
            .collect()
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
    fn exited_tasks_drop_from_liveness_list_but_keep_tail_logs_for_one_poll() {
        let task_id = FIRST_TASK_ID;
        let mut manager = NativeTaskManager::default();
        manager.next_task_id = task_id + 1;
        manager.tasks.insert(
            task_id,
            Arc::new(Mutex::new(Task {
                name: "prog".to_string(),
                paused: false,
                program: Some(test_running_program_with_wasm_output(b"out", b"err")),
                completed_logs: None,
            })),
        );

        let mut list_became_empty = false;
        for _ in 0..50 {
            if manager.get_task_list().is_empty() {
                list_became_empty = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(list_became_empty);

        let task = manager.get_task(task_id as ProgramHandle).unwrap();
        let logs = task.lock().unwrap().poll_log(None, 10);
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].1.log, "err");
        assert_eq!(logs[1].1.log, "out");

        assert!(manager.get_task_list().is_empty());
        assert!(manager.get_task(task_id as ProgramHandle).is_none());
        assert!(manager.tasks.is_empty());
        assert!(manager.completed_tasks.is_empty());
    }
}
