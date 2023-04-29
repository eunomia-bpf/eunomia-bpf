//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    collections::HashMap,
    io::{Cursor, Write},
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        Arc, Mutex, RwLock,
    },
    thread::JoinHandle,
    time::Duration,
};

use bpf_loader_lib::{
    export_event::{EventHandler, ExportFormatType, ReceivedEventData},
    meta::ComposedObject,
    skeleton::{builder::BpfSkeletonBuilder, handle::PollingHandle},
};
use tempdir::TempDir;
use wasm_bpf_rs::{
    handle::WasmProgramHandle, pipe::ReadableWritePipe, run_wasm_bpf_module_async, Config,
};

use crate::{
    config::ProgramType,
    error::{Error, Result},
    tar_reader::unpack_tar,
};

use super::{
    client::{ProgramDesc, ProgramStatus},
    LogEntry, ProgramHandle,
};

pub(crate) enum BtfArchivePath {
    None,
    WithoutTempdir(String),
    WithTempdir(String, TempDir),
}

impl BtfArchivePath {
    pub(crate) fn extract_archive_path(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::WithoutTempdir(ref p) | Self::WithTempdir(ref p, _) => Some(p.as_str()),
        }
    }
    pub(crate) fn extract_tempdir(self) -> Option<TempDir> {
        match self {
            Self::WithTempdir(_, t) => Some(t),
            _ => None,
        }
    }
}

/// The first task id
pub const FIRST_TASK_ID: usize = 1;

/// A helper struct to manage running tasks
pub struct NativeTaskManager {
    next_task_id: AtomicUsize,
    // Why use Mutex not RwLock? Because something in Task (WasmProgramHandle) is not Sync
    tasks: HashMap<usize, Arc<Mutex<Task>>>,
}
impl Default for NativeTaskManager {
    fn default() -> NativeTaskManager {
        NativeTaskManager {
            next_task_id: AtomicUsize::new(FIRST_TASK_ID),
            tasks: HashMap::default(),
        }
    }
}
impl NativeTaskManager {
    fn clean_dead_tasks(&mut self) {
        let ids_to_drop = self
            .tasks
            .iter()
            .filter(|(_, v)| v.lock().unwrap().died())
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        ids_to_drop.into_iter().for_each(|v| {
            self.tasks.remove(&v);
        });
    }
    /// Get a reference to a task
    pub fn get_task(&self, handle: ProgramHandle) -> Option<Arc<Mutex<Task>>> {
        self.tasks.get(&(handle as usize)).cloned()
    }

    /// Get task lists. Contained running and paused ones
    pub fn get_task_list(&mut self) -> Vec<ProgramDesc> {
        self.clean_dead_tasks();
        self.tasks
            .iter_mut()
            .map(|(id, task)| {
                let guard = task.lock().unwrap();
                ProgramDesc {
                    id: *id as ProgramHandle,
                    name: guard.name.clone(),
                    status: if guard.running {
                        ProgramStatus::Running
                    } else {
                        ProgramStatus::Paused
                    },
                }
            })
            .collect()
    }
    /// Terminate a task
    pub fn terminate_task(&mut self, handle: ProgramHandle) -> Result<()> {
        let task = self
            .tasks
            .remove(&(handle as usize))
            .ok_or_else(|| Error::Bpf(format!("Invalid handle: {}", handle)))?;
        let task = match Arc::try_unwrap(task) {
            Ok(v) => v.into_inner().unwrap(),
            Err(task) => {
                self.tasks.insert(handle as usize, task);
                return Err(Error::Bpf(
                    "Some others is holding a reference to the Task, cannot terminate the program"
                        .to_string(),
                ));
            }
        };
        match task.inner_impl {
            TaskImpl::Wasm {
                thread_handle,
                should_exit,
                mut prog_handle, // We cant drop it before we kill the wasm program
            } => {
                prog_handle
                    .terminate()
                    .map_err(|e| Error::Wasm(format!("Failed to terminate wasm program: {}", e)))?;

                // Notify the copying thread to exit
                should_exit.store(true, std::sync::atomic::Ordering::Relaxed);

                if let Err(e) = thread_handle
                    .join()
                    .map_err(|_| Error::ThreadJoin(format!("Failed to join")))?
                {
                    if format!("{:?}", e).contains("Wasm program terminated") {
                    } else {
                        return Err(Error::Bpf(format!(
                            "Failed to wait for the worker: {:?}",
                            e
                        )));
                    }
                }
            }
            TaskImpl::BpfLoader {
                polling_handle,
                join_handle,
                ..
            } => {
                polling_handle.terminate();
                join_handle
                    .join()
                    .map_err(|_| Error::ThreadJoin(format!("Failed to join")))?
                    .map_err(|e| {
                        Error::Bpf(format!("Failed to wait for the thread's exiting: {:?}", e))
                    })?;
            }
        }
        Ok(())
    }
    /// Start a task
    pub fn start_task(
        &mut self,
        name: impl Into<String>,
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> Result<usize> {
        let id = self
            .next_task_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (buf, ty, btf) = if matches!(prog_type, ProgramType::Tar) {
            let v = unpack_tar(prog_buf)?;
            (v.0, ProgramType::JsonEunomia, v.1)
        } else {
            (
                prog_buf.to_vec(),
                prog_type,
                match btf_archive_path {
                    Some(v) => BtfArchivePath::WithoutTempdir(v),
                    None => BtfArchivePath::None,
                },
            )
        };
        let log_buffer = Arc::new(RwLock::new(Vec::<(usize, LogEntry)>::new()));
        let log_cursor = Arc::new(AtomicUsize::new(0));
        let task = match ty {
            ProgramType::JsonEunomia => {
                let log_buffer_inner = log_buffer.clone();
                let log_cursor_inner = log_cursor.clone();
                let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
                let mut package = serde_json::from_slice::<ComposedObject>(&buf).map_err(|e| {
                    Error::InvalidParam(format!("Failed to deserialize package to object: {}", e))
                })?;
                let arg_parser = package
                    .meta
                    .build_argument_parser()
                    .map_err(|e| Error::Bpf(format!("Failed to build argument parser: {}", e)))?;
                let matches = arg_parser
                    .try_get_matches_from(args)
                    .map_err(|e| Error::Bpf(format!("Failed to parse argument: {}", e)))?;
                package
                    .meta
                    .parse_arguments_and_fill_skeleton_variables(
                        &matches,
                        bpf_loader_lib::meta::arg_parser::UnpresentVariableAction::FillWithZero,
                    )
                    .map_err(|e| Error::Bpf(format!("Failed to parse arguments: {}", e)))?;
                let btf_path = btf.extract_archive_path().map(|e| e.to_string());
                let join_handle = std::thread::spawn(move || {
                    let skel = BpfSkeletonBuilder::from_json_package(&package, btf_path.as_deref())
                        .build()
                        .map_err(|e| Error::Bpf(format!("Failed to build skeleton: {}", e)))?
                        .load_and_attach()
                        .map_err(|e| Error::Bpf(format!("Failed to load and attach: {}", e)))?;
                    tx.send(skel.create_poll_handle()).unwrap();
                    skel.wait_and_poll_to_handler(
                        if export_json {
                            ExportFormatType::Json
                        } else {
                            ExportFormatType::PlainText
                        },
                        Some(Arc::new(MyEventHandler {
                            log_buffer: log_buffer_inner,
                            log_cursor: log_cursor_inner,
                        })),
                        None,
                    )
                    .unwrap();
                    Result::Ok(())
                });
                match rx.recv() {
                    Ok(v) => {
                        let done = join_handle.is_finished();
                        Task {
                            inner_impl: TaskImpl::BpfLoader {
                                polling_handle: v,
                                join_handle,
                                btf_archive_tempdir: btf.extract_tempdir(),
                            },
                            log_buffer,
                            running: !done,
                            name: name.into(),
                            next_cursor: log_cursor,
                        }
                    }
                    Err(e) => {
                        return Err(Error::Bpf(format!(
                            "Failed to start polling: {:?}, {}",
                            join_handle.join().unwrap().unwrap_err(),
                            e
                        )));
                    }
                }
            }
            ProgramType::WasmModule => {
                let log_buffer_inner = log_buffer.clone();
                let log_cursor_inner = log_cursor.clone();
                let should_exit = Arc::new(AtomicBool::new(false));
                let stdout = ReadableWritePipe::new_vec_buf();
                let stderr = ReadableWritePipe::new_vec_buf();
                {
                    let should_exit = should_exit.clone();
                    let stdout = stdout.clone();
                    let stderr = stderr.clone();
                    // start a new thread to copy things from wasm's stdout/stderr to log_buffer
                    std::thread::spawn(move || {
                        let mut stdout = StepFetcher::new(stdout);
                        let mut stderr = StepFetcher::new(stderr);
                        while !should_exit.load(std::sync::atomic::Ordering::Relaxed) {
                            let log_entries = {
                                let mut val = vec![];
                                if let Some(v) = stderr.fetch() {
                                    val.push(LogEntry {
                                        log: String::from_utf8(v).unwrap(),
                                        timestamp: chrono::Local::now().timestamp() as _,
                                        log_type: super::LogType::Stderr,
                                    });
                                }
                                if let Some(v) = stdout.fetch() {
                                    val.push(LogEntry {
                                        log: String::from_utf8(v).unwrap(),
                                        timestamp: chrono::Local::now().timestamp() as _,
                                        log_type: super::LogType::Stdout,
                                    });
                                }
                                val
                            };
                            let start_id = log_cursor_inner
                                .fetch_add(log_entries.len(), std::sync::atomic::Ordering::Relaxed);

                            log_buffer_inner.write().unwrap().extend(
                                log_entries
                                    .into_iter()
                                    .enumerate()
                                    .map(|(a, b)| (a + start_id, b)),
                            );
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    });
                }
                let (h1, h2) = run_wasm_bpf_module_async(
                    &buf,
                    args,
                    Config {
                        stderr: Box::new(stderr),
                        stdout: Box::new(stdout),
                        ..Default::default()
                    },
                )
                .map_err(|e| Error::Wasm(format!("Failed to run wasm bpf module: {}", e)))?;
                let done = h2.is_finished();
                Task {
                    inner_impl: TaskImpl::Wasm {
                        prog_handle: h1,
                        thread_handle: h2,
                        should_exit,
                    },
                    log_buffer,
                    running: !done,
                    name: name.into(),
                    next_cursor: log_cursor,
                }
            }
            _ => unreachable!(),
        };
        self.tasks.insert(id, Arc::new(Mutex::new(task)));
        Ok(id)
    }
}

/// A running task
pub struct Task {
    inner_impl: TaskImpl,
    running: bool,
    log_buffer: Arc<RwLock<Vec<(usize, LogEntry)>>>,
    name: String,
    #[allow(unused)]
    next_cursor: Arc<AtomicUsize>,
}

impl Task {
    /// Poll logs with cursor >= the input one; and drops any logs before this
    /// If cursor is none, poll from the minimum cursor within the buffer
    pub fn poll_log(&self, cursor: Option<usize>, maximum: usize) -> Vec<(usize, LogEntry)> {
        let mut guard = self.log_buffer.write().unwrap();
        if guard.is_empty() {
            return vec![];
        }
        if let Some(cursor) = cursor {
            // Let's drop logs with timestamp less than `timestamp`
            // No need to use binary search, since dropping elements itself is O(n)
            let new_logs = guard
                .iter()
                .filter_map(|v| if v.0 >= cursor { Some(v.clone()) } else { None })
                .collect::<Vec<_>>();
            *guard = new_logs;
        }
        // Now let's fetch the maximum number of logs..
        let max_count = maximum.min(guard.len());
        guard[..max_count].to_vec()
    }
    fn died(&self) -> bool {
        match &self.inner_impl {
            TaskImpl::BpfLoader { join_handle, .. } => join_handle.is_finished(),
            TaskImpl::Wasm { thread_handle, .. } => thread_handle.is_finished(),
        }
    }
    /// Set the pause state of this task
    pub fn set_pause(&mut self, p: bool) -> Result<()> {
        match &mut self.inner_impl {
            TaskImpl::BpfLoader { polling_handle, .. } => {
                polling_handle.set_pause(p);
            }
            TaskImpl::Wasm {
                ref mut prog_handle,
                ..
            } => (if p {
                prog_handle.pause()
            } else {
                prog_handle.resume()
            })
            .map_err(|e| Error::Other(format!("Failed to set pause state: {}", e)))?,
        }
        self.running = !p;
        Ok(())
    }
}

enum TaskImpl {
    Wasm {
        prog_handle: WasmProgramHandle,
        thread_handle: JoinHandle<anyhow::Result<()>>,
        should_exit: Arc<AtomicBool>,
    },
    BpfLoader {
        polling_handle: PollingHandle,
        join_handle: JoinHandle<Result<()>>,
        #[allow(unused)]
        /// It's only be used to keep liveness
        btf_archive_tempdir: Option<TempDir>,
    },
}

struct MyEventHandler {
    log_buffer: Arc<RwLock<Vec<(usize, LogEntry)>>>,
    log_cursor: Arc<AtomicUsize>,
}

impl EventHandler for MyEventHandler {
    fn handle_event(
        &self,
        _context: Option<Arc<dyn std::any::Any>>,
        data: bpf_loader_lib::export_event::ReceivedEventData,
    ) {
        let mut guard = self.log_buffer.write().unwrap();
        match data {
            ReceivedEventData::JsonText(j) | ReceivedEventData::PlainText(j) => {
                guard.push((
                    self.log_cursor
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                    LogEntry {
                        log: j.to_string(),
                        timestamp: chrono::Local::now().timestamp() as u64,
                        log_type: super::LogType::Plain,
                    },
                ));
            }
            _ => (),
        }
    }
}

struct StepFetcher<W: Write> {
    last_idx: usize,
    buf: ReadableWritePipe<W>,
}

impl StepFetcher<Cursor<Vec<u8>>> {
    fn fetch(&mut self) -> Option<Vec<u8>> {
        let vec_ref = self.buf.get_read_lock();
        let vec_ref = vec_ref.get_ref();

        if vec_ref.len() > self.last_idx {
            let c = Some(vec_ref[self.last_idx..].to_vec());
            self.last_idx = vec_ref.len();
            c
        } else {
            None
        }
    }
    fn new(buf: ReadableWritePipe<Cursor<Vec<u8>>>) -> Self {
        Self { buf, last_idx: 0 }
    }
}
