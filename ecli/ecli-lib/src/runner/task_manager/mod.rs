//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
//! Deprecated compatibility shim for the pre-issue-382 task manager API.
#![allow(deprecated)]

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Instant,
};

use crate::{
    config::ProgramType,
    error::{Error, Result},
    runner::{
        client::{ProgramDesc, ProgramStatus},
        compat_completion_retention,
        native::{NativeRunner, RunningProgram},
        LogEntry, ProgramHandle,
    },
};

/// The first compatibility task id.
pub const FIRST_TASK_ID: usize = 1;

/// Deprecated compatibility task manager preserved for downstream callers.
pub struct NativeTaskManager {
    next_task_id: AtomicUsize,
    tasks: RwLock<HashMap<usize, Arc<Mutex<Task>>>>,
    completed_tasks: RwLock<HashMap<usize, CompletedTask>>,
}

impl Default for NativeTaskManager {
    fn default() -> Self {
        Self {
            next_task_id: AtomicUsize::new(FIRST_TASK_ID),
            tasks: RwLock::new(HashMap::new()),
            completed_tasks: RwLock::new(HashMap::new()),
        }
    }
}

impl NativeTaskManager {
    fn prune_expired_completed_tasks(&self, now: Instant) {
        self.completed_tasks
            .write()
            .unwrap()
            .retain(|_, task| task.retained_until > now);
    }

    fn retire_exited_tasks(&self) {
        let completed_ids = self
            .tasks
            .read()
            .unwrap()
            .iter()
            .filter_map(|(id, task)| {
                let task = task.lock().unwrap();
                if !task.has_exited() {
                    return None;
                }
                Some((*id, task.completed_snapshot()))
            })
            .collect::<Vec<_>>();

        let mut tasks = self.tasks.write().unwrap();
        let mut completed_tasks = self.completed_tasks.write().unwrap();
        for (id, completed_task) in completed_ids {
            tasks.remove(&id);
            completed_tasks.insert(id, completed_task);
        }
    }

    fn refresh_completed_tasks(&self) {
        let now = Instant::now();
        self.retire_exited_tasks();
        self.prune_expired_completed_tasks(now);
    }

    /// Get a reference to a compatibility task.
    pub fn get_task(&self, handle: ProgramHandle) -> Option<Arc<Mutex<Task>>> {
        self.refresh_completed_tasks();
        self.tasks
            .read()
            .unwrap()
            .get(&(handle as usize))
            .cloned()
            .or_else(|| {
                self.completed_tasks
                    .read()
                    .unwrap()
                    .get(&(handle as usize))
                    .map(|task| Arc::new(Mutex::new(Task::from_completed(task))))
            })
    }

    /// Get all active compatibility tasks. Finished tasks remain readable for
    /// a short post-exit window so callers can still fetch tail logs after
    /// observing liveness while they monitor other tasks.
    pub fn get_task_list(&mut self) -> Vec<ProgramDesc> {
        self.refresh_completed_tasks();
        self.tasks
            .read()
            .unwrap()
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
        self.refresh_completed_tasks();
        let task = if let Some(task) = self.tasks.write().unwrap().remove(&(handle as usize)) {
            task
        } else if self
            .completed_tasks
            .write()
            .unwrap()
            .remove(&(handle as usize))
            .is_some()
        {
            return Ok(());
        } else {
            return Err(Error::Bpf(format!("Invalid handle: {}", handle)));
        };
        let task = match Arc::try_unwrap(task) {
            Ok(task) => task.into_inner().unwrap(),
            Err(task) => {
                self.tasks.write().unwrap().insert(handle as usize, task);
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
        self.refresh_completed_tasks();
        let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
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
        self.tasks
            .write()
            .unwrap()
            .insert(task_id, Arc::new(Mutex::new(task)));
        Ok(task_id)
    }
}

struct CompletedTask {
    name: String,
    logs: Vec<(usize, LogEntry)>,
    retained_until: Instant,
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
        let retention = compat_completion_retention();
        CompletedTask {
            name: self.name.clone(),
            logs: self
                .program
                .as_ref()
                .map(|program| program.fetch_logs(None, Some(usize::MAX)))
                .unwrap_or_else(|| self.completed_logs.clone().unwrap_or_default()),
            retained_until: self
                .program
                .as_ref()
                .and_then(|program| program.retained_until(retention))
                .expect("completed task must expose an exit timestamp"),
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
    use crate::runner::native::{
        test_running_program_with_delayed_wasm_output, test_running_program_with_wasm_output,
    };

    fn wait_until_task_exited(task: &Arc<Mutex<Task>>) {
        for _ in 0..50 {
            if task.lock().unwrap().has_exited() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("task did not exit in time");
    }

    #[test]
    fn empty_manager_reports_no_tasks() {
        let mut manager = NativeTaskManager::default();
        assert!(manager.get_task_list().is_empty());
    }

    #[test]
    fn completed_tasks_keep_tail_logs_for_a_bounded_window() {
        let completed_task_id = FIRST_TASK_ID;
        let active_task_id = FIRST_TASK_ID + 1;
        let retention = crate::runner::compat_completion_retention();
        let mut manager = NativeTaskManager::default();
        manager
            .next_task_id
            .store(active_task_id + 1, Ordering::Relaxed);
        manager.tasks.write().unwrap().insert(
            completed_task_id,
            Arc::new(Mutex::new(Task {
                name: "completed".to_string(),
                paused: false,
                program: Some(test_running_program_with_wasm_output(b"out", b"err")),
                completed_logs: None,
            })),
        );
        manager.tasks.write().unwrap().insert(
            active_task_id,
            Arc::new(Mutex::new(Task {
                name: "active".to_string(),
                paused: false,
                program: Some(test_running_program_with_delayed_wasm_output(
                    retention.checked_mul(3).unwrap(),
                    b"",
                    b"",
                )),
                completed_logs: None,
            })),
        );

        let mut list_only_shows_active_task = false;
        for _ in 0..50 {
            let list = manager.get_task_list();
            if list.len() == 1 && list[0].id == active_task_id as ProgramHandle {
                list_only_shows_active_task = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert!(list_only_shows_active_task);

        for _ in 0..2 {
            let list = manager.get_task_list();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].id, active_task_id as ProgramHandle);

            let task = manager
                .get_task(completed_task_id as ProgramHandle)
                .unwrap();
            let logs = task.lock().unwrap().poll_log(None, 10);
            assert_eq!(logs.len(), 2);
            assert_eq!(logs[0].1.log, "err");
            assert_eq!(logs[1].1.log, "out");
        }

        std::thread::sleep(retention + std::time::Duration::from_millis(50));
        let list = manager.get_task_list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, active_task_id as ProgramHandle);
        assert!(manager
            .get_task(completed_task_id as ProgramHandle)
            .is_none());
        assert!(!manager
            .tasks
            .read()
            .unwrap()
            .contains_key(&completed_task_id));
        assert!(!manager
            .completed_tasks
            .read()
            .unwrap()
            .contains_key(&completed_task_id));
        manager
            .terminate_task(active_task_id as ProgramHandle)
            .unwrap();

        assert!(manager.tasks.read().unwrap().is_empty());
        assert!(manager.completed_tasks.read().unwrap().is_empty());
    }

    #[test]
    fn quiet_completed_tasks_expire_without_explicit_cleanup() {
        let task_id = FIRST_TASK_ID;
        let retention = crate::runner::compat_completion_retention();
        let mut manager = NativeTaskManager::default();
        manager.next_task_id.store(task_id + 1, Ordering::Relaxed);
        manager.tasks.write().unwrap().insert(
            task_id,
            Arc::new(Mutex::new(Task {
                name: "quiet".to_string(),
                paused: false,
                program: Some(test_running_program_with_wasm_output(b"", b"")),
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
        assert!(task.lock().unwrap().poll_log(None, 10).is_empty());
        assert!(manager.get_task_list().is_empty());
        let task = manager.get_task(task_id as ProgramHandle).unwrap();
        assert!(task.lock().unwrap().poll_log(None, 10).is_empty());

        std::thread::sleep(retention + std::time::Duration::from_millis(50));
        assert!(manager.get_task_list().is_empty());
        assert!(manager.get_task(task_id as ProgramHandle).is_none());
        assert!(manager.tasks.read().unwrap().is_empty());
        assert!(manager.completed_tasks.read().unwrap().is_empty());
    }

    #[test]
    fn get_task_path_retires_and_prunes_completed_tasks_without_list_polls() {
        let task_id = FIRST_TASK_ID;
        let retention = crate::runner::compat_completion_retention();
        let manager = NativeTaskManager::default();
        manager.next_task_id.store(task_id + 1, Ordering::Relaxed);
        manager.tasks.write().unwrap().insert(
            task_id,
            Arc::new(Mutex::new(Task {
                name: "completed".to_string(),
                paused: false,
                program: Some(test_running_program_with_wasm_output(b"out", b"err")),
                completed_logs: None,
            })),
        );

        let task = manager
            .tasks
            .read()
            .unwrap()
            .get(&task_id)
            .cloned()
            .expect("task should exist");
        wait_until_task_exited(&task);

        let snapshot = manager.get_task(task_id as ProgramHandle).unwrap();
        let logs = snapshot.lock().unwrap().poll_log(None, 10);
        assert_eq!(logs.len(), 2);
        assert!(!manager.tasks.read().unwrap().contains_key(&task_id));
        assert!(manager
            .completed_tasks
            .read()
            .unwrap()
            .contains_key(&task_id));

        std::thread::sleep(retention + std::time::Duration::from_millis(50));
        assert!(manager.get_task(task_id as ProgramHandle).is_none());
        assert!(!manager.tasks.read().unwrap().contains_key(&task_id));
        assert!(!manager
            .completed_tasks
            .read()
            .unwrap()
            .contains_key(&task_id));
    }

    #[test]
    fn idle_gaps_do_not_extend_get_task_retention_window() {
        let task_id = FIRST_TASK_ID;
        let retention = crate::runner::compat_completion_retention();
        let manager = NativeTaskManager::default();
        manager.tasks.write().unwrap().insert(
            task_id,
            Arc::new(Mutex::new(Task {
                name: "completed".to_string(),
                paused: false,
                program: Some(test_running_program_with_wasm_output(b"out", b"err")),
                completed_logs: None,
            })),
        );

        let task = manager
            .tasks
            .read()
            .unwrap()
            .get(&task_id)
            .cloned()
            .expect("task should exist");
        wait_until_task_exited(&task);
        std::thread::sleep(retention + std::time::Duration::from_millis(50));

        assert!(manager.get_task(task_id as ProgramHandle).is_none());
        assert!(!manager.tasks.read().unwrap().contains_key(&task_id));
        assert!(!manager
            .completed_tasks
            .read()
            .unwrap()
            .contains_key(&task_id));
    }
}
