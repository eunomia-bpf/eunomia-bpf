//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    io::{Cursor, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    thread::JoinHandle,
};

use bpf_compatible_rs::{tempfile::TempDir, unpack_tar};
use bpf_loader_lib::{
    export_event::{EventHandler, ExportFormatType, ReceivedEventData},
    meta::ComposedObject,
    skeleton::{builder::BpfSkeletonBuilder, handle::PollingHandle},
};
use wasm_bpf_rs::{
    handle::WasmProgramHandle, pipe::ReadableWritePipe, run_wasm_bpf_module_async, Config,
};

use crate::{
    config::ProgramType,
    error::{Error, Result},
};

use super::{LogEntry, LogType, DEFAULT_MAXIMUM_LOG_ENTRIES};

enum BtfArchivePath {
    None,
    WithoutTempdir(String),
    WithTempdir(String, TempDir),
}

impl BtfArchivePath {
    fn extract_archive_path(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::WithoutTempdir(path) | Self::WithTempdir(path, _) => Some(path.as_str()),
        }
    }

    fn extract_tempdir(self) -> Option<TempDir> {
        match self {
            Self::WithTempdir(_, tempdir) => Some(tempdir),
            _ => None,
        }
    }
}

/// Start and manage a single local program execution.
pub struct NativeRunner;

impl NativeRunner {
    pub fn start_program(
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> Result<RunningProgram> {
        Ok(RunningProgram {
            task: Task::start(prog_buf, prog_type, export_json, args, btf_archive_path)?,
        })
    }
}

/// A running local program. The CLI only needs incremental logs, liveness, and termination.
pub struct RunningProgram {
    task: Task,
}

impl RunningProgram {
    pub fn fetch_logs(
        &self,
        cursor: Option<usize>,
        maximum_count: Option<usize>,
    ) -> Vec<(usize, LogEntry)> {
        self.task
            .poll_logs(cursor, maximum_count.unwrap_or(DEFAULT_MAXIMUM_LOG_ENTRIES))
    }

    pub fn has_exited(&self) -> bool {
        self.task.has_exited()
    }

    pub fn set_pause(&mut self, pause: bool) -> Result<()> {
        self.task.set_pause(pause)
    }

    pub fn terminate(self) -> Result<()> {
        self.task.terminate()
    }
}

struct Task {
    inner_impl: TaskImpl,
    log_buffer: Arc<RwLock<Vec<(usize, LogEntry)>>>,
    log_cursor: Arc<AtomicUsize>,
}

impl Task {
    fn start(
        prog_buf: &[u8],
        prog_type: ProgramType,
        export_json: bool,
        args: &[String],
        btf_archive_path: Option<String>,
    ) -> Result<Self> {
        let (buf, ty, btf) = if matches!(prog_type, ProgramType::Tar) {
            let unpacked =
                unpack_tar(prog_buf).map_err(|e| Error::Tar(format!("Failed to unpack: {}", e)))?;
            (
                unpacked.0,
                ProgramType::JsonEunomia,
                match unpacked.1 {
                    Some(archive) => BtfArchivePath::WithTempdir(
                        archive.0.to_string_lossy().to_string(),
                        archive.1,
                    ),
                    None => BtfArchivePath::None,
                },
            )
        } else {
            (
                prog_buf.to_vec(),
                prog_type,
                match btf_archive_path {
                    Some(path) => BtfArchivePath::WithoutTempdir(path),
                    None => BtfArchivePath::None,
                },
            )
        };

        let log_buffer = Arc::new(RwLock::new(Vec::<(usize, LogEntry)>::new()));
        let log_cursor = Arc::new(AtomicUsize::new(0));

        let inner_impl = match ty {
            ProgramType::JsonEunomia => {
                let log_buffer_inner = Arc::clone(&log_buffer);
                let log_cursor_inner = Arc::clone(&log_cursor);
                let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
                let mut package = serde_json::from_slice::<ComposedObject>(&buf).map_err(|e| {
                    Error::InvalidParam(format!("Failed to deserialize package to object: {}", e))
                })?;
                let arg_parser = package
                    .meta
                    .build_argument_parser()
                    .map_err(|e| Error::Bpf(format!("Failed to build argument parser: {}", e)))?;
                let mut args = args.to_vec();
                args.insert(0, String::from("prog"));
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
                let btf_path = btf.extract_archive_path().map(|path| path.to_string());
                let join_handle = std::thread::spawn(move || {
                    let skel = BpfSkeletonBuilder::from_json_package(&package, btf_path.as_deref())
                        .build()
                        .map_err(|e| Error::Bpf(format!("Failed to build skeleton: {:?}", e)))?
                        .load_and_attach()
                        .map_err(|e| Error::Bpf(format!("Failed to load and attach: {:?}", e)))?;
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
                    Ok(polling_handle) => TaskImpl::BpfLoader {
                        polling_handle,
                        join_handle,
                        btf_archive_tempdir: btf.extract_tempdir(),
                    },
                    Err(e) => {
                        return Err(Error::Bpf(format!(
                            "Failed to start polling: {:?}, {:?}",
                            join_handle.join().unwrap().unwrap_err(),
                            e
                        )));
                    }
                }
            }
            ProgramType::WasmModule => {
                let stdout = ReadableWritePipe::new_vec_buf();
                let stderr = ReadableWritePipe::new_vec_buf();
                let (prog_handle, join_handle) = run_wasm_bpf_module_async(
                    &buf,
                    args,
                    Config {
                        stderr: Box::new(stderr.clone()),
                        stdout: Box::new(stdout.clone()),
                        ..Default::default()
                    },
                )
                .map_err(|e| Error::Wasm(format!("Failed to run wasm bpf module: {}", e)))?;

                TaskImpl::Wasm {
                    prog_handle,
                    join_handle,
                    log_collector: Mutex::new(WasmLogCollector {
                        stdout: StepFetcher::new(stdout),
                        stderr: StepFetcher::new(stderr),
                    }),
                }
            }
            _ => unreachable!(),
        };

        Ok(Self {
            inner_impl,
            log_buffer,
            log_cursor,
        })
    }

    fn poll_logs(&self, cursor: Option<usize>, maximum: usize) -> Vec<(usize, LogEntry)> {
        self.collect_pending_logs();
        let mut guard = self.log_buffer.write().unwrap();
        if guard.is_empty() {
            return vec![];
        }
        if let Some(cursor) = cursor {
            let new_logs = guard
                .iter()
                .filter_map(|entry| {
                    if entry.0 >= cursor {
                        Some(entry.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            *guard = new_logs;
        }
        let max_count = maximum.min(guard.len());
        guard[..max_count].to_vec()
    }

    fn has_exited(&self) -> bool {
        match &self.inner_impl {
            TaskImpl::BpfLoader { join_handle, .. } => join_handle.is_finished(),
            TaskImpl::Wasm { join_handle, .. } => join_handle.is_finished(),
        }
    }

    fn set_pause(&mut self, pause: bool) -> Result<()> {
        match &mut self.inner_impl {
            TaskImpl::BpfLoader { polling_handle, .. } => {
                polling_handle.set_pause(pause);
            }
            TaskImpl::Wasm { prog_handle, .. } => (if pause {
                prog_handle.pause()
            } else {
                prog_handle.resume()
            })
            .map_err(|e| Error::Other(format!("Failed to set pause state: {}", e)))?,
        }
        Ok(())
    }

    fn collect_pending_logs(&self) {
        if let TaskImpl::Wasm { log_collector, .. } = &self.inner_impl {
            let mut guard = log_collector.lock().unwrap();
            guard.drain(&self.log_buffer, &self.log_cursor);
        }
    }

    fn terminate(self) -> Result<()> {
        let Task {
            inner_impl,
            log_buffer,
            log_cursor,
        } = self;

        match inner_impl {
            TaskImpl::Wasm {
                prog_handle,
                join_handle,
                log_collector,
            } => {
                {
                    let mut guard = log_collector.lock().unwrap();
                    guard.drain(&log_buffer, &log_cursor);
                }

                if !join_handle.is_finished() {
                    prog_handle.terminate().map_err(|e| {
                        Error::Wasm(format!("Failed to terminate wasm program: {}", e))
                    })?;
                }

                if let Err(e) = join_handle
                    .join()
                    .map_err(|_| Error::ThreadJoin("Failed to join".to_string()))?
                {
                    let formatted = format!("{:?}", e);
                    if !formatted.contains("Wasm program terminated")
                        && !formatted.contains("receiving on a closed channel")
                    {
                        return Err(Error::Bpf(format!(
                            "Failed to wait for the worker: {:?}",
                            e
                        )));
                    }
                }

                let mut guard = log_collector.lock().unwrap();
                guard.drain(&log_buffer, &log_cursor);
            }
            TaskImpl::BpfLoader {
                polling_handle,
                join_handle,
                ..
            } => {
                if !join_handle.is_finished() {
                    polling_handle.terminate();
                }
                join_handle
                    .join()
                    .map_err(|_| Error::ThreadJoin("Failed to join".to_string()))?
                    .map_err(|e| {
                        Error::Bpf(format!("Failed to wait for the thread's exiting: {:?}", e))
                    })?;
            }
        }
        Ok(())
    }
}

enum TaskImpl {
    Wasm {
        prog_handle: WasmProgramHandle,
        join_handle: JoinHandle<anyhow::Result<()>>,
        log_collector: Mutex<WasmLogCollector>,
    },
    BpfLoader {
        polling_handle: PollingHandle,
        join_handle: JoinHandle<Result<()>>,
        #[allow(unused)]
        // Kept only to preserve the extracted archive lifetime while the task is running.
        btf_archive_tempdir: Option<TempDir>,
    },
}

struct WasmLogCollector {
    stdout: StepFetcher<Cursor<Vec<u8>>>,
    stderr: StepFetcher<Cursor<Vec<u8>>>,
}

impl WasmLogCollector {
    fn drain(
        &mut self,
        log_buffer: &Arc<RwLock<Vec<(usize, LogEntry)>>>,
        log_cursor: &Arc<AtomicUsize>,
    ) {
        let mut log_entries = Vec::new();
        if let Some(stderr_log) = self.stderr.fetch() {
            log_entries.push(LogEntry {
                log: String::from_utf8(stderr_log).unwrap(),
                timestamp: chrono::Local::now().timestamp() as _,
                log_type: LogType::Stderr,
            });
        }
        if let Some(stdout_log) = self.stdout.fetch() {
            log_entries.push(LogEntry {
                log: String::from_utf8(stdout_log).unwrap(),
                timestamp: chrono::Local::now().timestamp() as _,
                log_type: LogType::Stdout,
            });
        }
        let start_id = log_cursor.fetch_add(log_entries.len(), Ordering::Relaxed);
        log_buffer.write().unwrap().extend(
            log_entries
                .into_iter()
                .enumerate()
                .map(|(offset, entry)| (offset + start_id, entry)),
        );
    }
}

struct MyEventHandler {
    log_buffer: Arc<RwLock<Vec<(usize, LogEntry)>>>,
    log_cursor: Arc<AtomicUsize>,
}

impl EventHandler for MyEventHandler {
    fn handle_event(&self, _context: Option<Arc<dyn std::any::Any>>, data: ReceivedEventData) {
        let mut guard = self.log_buffer.write().unwrap();
        match data {
            ReceivedEventData::JsonText(log) | ReceivedEventData::PlainText(log) => {
                guard.push((
                    self.log_cursor.fetch_add(1, Ordering::Relaxed),
                    LogEntry {
                        log: log.to_string(),
                        timestamp: chrono::Local::now().timestamp() as u64,
                        log_type: LogType::Plain,
                    },
                ));
            }
            _ => {}
        }
    }
}

struct StepFetcher<W: Write> {
    last_idx: usize,
    buf: ReadableWritePipe<W>,
}

impl StepFetcher<Cursor<Vec<u8>>> {
    fn new(buf: ReadableWritePipe<Cursor<Vec<u8>>>) -> Self {
        Self { buf, last_idx: 0 }
    }

    fn fetch(&mut self) -> Option<Vec<u8>> {
        let vec_ref = self.buf.get_read_lock();
        let vec_ref = vec_ref.get_ref();

        if vec_ref.len() > self.last_idx {
            let chunk = Some(vec_ref[self.last_idx..].to_vec());
            self.last_idx = vec_ref.len();
            chunk
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_program_rejects_invalid_wasm_module() {
        let args: Vec<String> = Vec::new();
        let err = NativeRunner::start_program(
            b"not a wasm module",
            ProgramType::WasmModule,
            false,
            &args,
            None,
        )
        .err()
        .expect("invalid wasm module should fail to start");
        assert!(matches!(err, Error::Wasm(_)));
    }

    #[test]
    fn event_handler_records_plain_logs() {
        let log_buffer = Arc::new(RwLock::new(Vec::new()));
        let handler = MyEventHandler {
            log_buffer: Arc::clone(&log_buffer),
            log_cursor: Arc::new(AtomicUsize::new(0)),
        };

        handler.handle_event(None, ReceivedEventData::PlainText("hello"));
        handler.handle_event(None, ReceivedEventData::JsonText("{\"ok\":true}"));

        let guard = log_buffer.read().unwrap();
        assert_eq!(guard.len(), 2);
        assert_eq!(guard[0].0, 0);
        assert_eq!(guard[0].1.log, "hello");
        assert_eq!(guard[1].0, 1);
        assert_eq!(guard[1].1.log, "{\"ok\":true}");
    }

    #[test]
    fn step_fetcher_returns_only_new_bytes() {
        let pipe = ReadableWritePipe::new_vec_buf();
        pipe.borrow().write_all(b"ab").unwrap();

        let mut fetcher = StepFetcher::new(pipe.clone());
        assert_eq!(fetcher.fetch(), Some(b"ab".to_vec()));
        assert_eq!(fetcher.fetch(), None);

        pipe.borrow().write_all(b"cd").unwrap();
        assert_eq!(fetcher.fetch(), Some(b"cd".to_vec()));
    }

    #[test]
    fn wasm_log_collector_flushes_pending_output() {
        let stdout = ReadableWritePipe::new_vec_buf();
        let stderr = ReadableWritePipe::new_vec_buf();
        let mut collector = WasmLogCollector {
            stdout: StepFetcher::new(stdout.clone()),
            stderr: StepFetcher::new(stderr.clone()),
        };
        let log_buffer = Arc::new(RwLock::new(Vec::new()));
        let log_cursor = Arc::new(AtomicUsize::new(0));

        stdout.borrow().write_all(b"out").unwrap();
        stderr.borrow().write_all(b"err").unwrap();
        collector.drain(&log_buffer, &log_cursor);

        let guard = log_buffer.read().unwrap();
        assert_eq!(guard.len(), 2);
        assert_eq!(guard[0].0, 0);
        assert_eq!(guard[0].1.log, "err");
        assert_eq!(guard[0].1.log_type.to_string(), "STDERR");
        assert_eq!(guard[1].0, 1);
        assert_eq!(guard[1].1.log, "out");
        assert_eq!(guard[1].1.log_type.to_string(), "STDOUT");
    }
}
