//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use crate::config::ExportFormatType;
use crate::config::ProgramConfigData;
use crate::config::ProgramType;
use crate::error::EcliError;
use crate::runner::{
    models::{
        ListGet200Response, ListGet200ResponseTasksInner, LogPost200Response, StopPost200Response,
    },
    ListGetResponse, LogPostResponse, StartPostResponse, StopPostResponse,
};

use eunomia_rs::TempDir;
use swagger::ApiError;

use wasm_bpf_rs::{
    handle::WasmProgramHandle, pipe::ReadableWritePipe, run_wasm_bpf_module_async, Config,
};

use std::{
    {collections::HashMap, fs::write},
    {io::Cursor, sync::Arc},
};

use tokio::sync::Mutex;

use super::server::StartReq;

#[derive(Clone)]
pub struct ServerData {
    pub wasm_tasks: HashMap<usize, WasmModuleProgram>,
    pub json_tasks: HashMap<usize, JsonEunomiaProgram>,
    pub prog_info: HashMap<usize, (String, ProgramType)>,
    pub global_count: Arc<AtomicUsize>,
}

pub trait ProgStart {
    fn wasm_start(&mut self, startup_elem: StartReq) -> Result<i32, EcliError>;
    fn json_start(&mut self, startup_elem: StartReq) -> Result<i32, EcliError>;
    // fn json_start() -> ();
    fn tar_start(
        &mut self,
        startup_elem: StartReq,
        btf_data: Option<swagger::ByteArray>,
    ) -> Result<i32, ApiError>;
}

impl ProgStart for ServerData {
    fn wasm_start(&mut self, startup_elem: StartReq) -> Result<i32, EcliError> {
        let crate::runner::server::StartReq {
            program_name,
            program_data_buf,
            extra_params,
            ..
        } = startup_elem;

        let id = self.global_count.load(SeqCst) as usize;

        let stdout = ReadableWritePipe::new_vec_buf();
        let stderr = ReadableWritePipe::new_vec_buf();
        let config = Config::new(
            String::from("go-callback"),
            String::from("callback-wrapper"),
            Box::new(wasmtime_wasi::stdio::stdin()),
            Box::new(stdout.clone()),
            Box::new(stderr.clone()),
        );

        let (wasm_handle, _) = run_wasm_bpf_module_async(
            &program_data_buf.unwrap().as_slice(),
            &extra_params.unwrap(),
            config,
        )
        .unwrap();

        let wasm_log = LogMsg::new(stdout, stderr);

        self.wasm_tasks
            .insert(id, WasmModuleProgram::new(wasm_handle, wasm_log));

        self.prog_info
            .insert(id, (program_name.unwrap(), ProgramType::WasmModule));

        self.global_count.fetch_add(1, SeqCst);

        Ok(id as i32)
    }

    #[allow(unused)]
    fn json_start(&mut self, startup_elem: StartReq) -> Result<i32, EcliError> {
        let StartReq {
            program_name,
            program_data_buf,
            extra_params,
            ..
        } = startup_elem;
        let id = self.global_count.load(SeqCst) as usize;

        let _data = ProgramConfigData {
            url: String::default(),
            use_cache: false,
            btf_path: None,
            program_data_buf: program_data_buf.unwrap().as_slice().to_owned(),
            extra_arg: extra_params.unwrap(),
            prog_type: ProgramType::JsonEunomia,
            export_format_type: ExportFormatType::PlainText,
        };

        self.global_count.fetch_add(1, SeqCst);
        Ok(id as i32)
    }

    #[allow(unused)]
    fn tar_start(
        &mut self,
        startup_elem: StartReq,
        btf_data: Option<swagger::ByteArray>,
    ) -> Result<i32, ApiError> {
        let StartReq {
            program_name,
            program_data_buf,
            extra_params,
            btf_data,
            ..
        } = startup_elem;

        let id = self.global_count.load(SeqCst) as usize;
        let tmp_dir = TempDir::new();

        let tmp_data_dir = tmp_dir.map_err(|e| ApiError(e.to_string())).unwrap();

        // store btf_data
        let btf_data_file_path = tmp_data_dir.path().join("btf_data");
        if let Some(b) = btf_data {
            if write(&btf_data_file_path, b.as_slice()).is_err() {
                return Err(ApiError("Save btf data fail".into()));
            };
        };

        let _btf_path: Option<String> = if btf_data_file_path.exists() {
            Some(btf_data_file_path.as_path().display().to_string())
        } else {
            None
        };
        Err(ApiError("not implemented".to_string()))
    }
}

impl ServerData {
    pub fn new() -> Self {
        Self {
            wasm_tasks: HashMap::new(),
            json_tasks: HashMap::new(),
            prog_info: HashMap::new(),
            global_count: Arc::new(AtomicUsize::default()),
        }
    }

    pub fn get_log_follow(&self, id: &usize) -> Option<(String, String)> {
        let LogMsg {
            mut stdout,
            mut stderr,
        } = self.get_prog_log(id);

        Some((stdout.follow_log(), stderr.follow_log()))
    }

    pub fn get_log_full(&self, id: &usize) -> Option<(String, String)> {
        let LogMsg { stdout, stderr } = self.get_prog_log(id);

        Some((
            stdout.read_log_all().unwrap(),
            stderr.read_log_all().unwrap(),
        ))
    }

    pub fn get_type_of(&self, id: &usize) -> Option<ProgramType> {
        self.prog_info.get(id).map(|v| v.1.clone())
    }

    pub fn get_prog_log(&self, id: &usize) -> LogMsg {
        match self.get_type_of(id).unwrap() {
            ProgramType::WasmModule => self.wasm_tasks.get(id).unwrap().log_msg.clone(),
            ProgramType::JsonEunomia => self.json_tasks.get(id).unwrap().log_msg.clone(),
            _ => unimplemented!(),
        }
    }

    pub fn list_all_task(&self) -> Vec<ListGet200ResponseTasksInner> {
        self.prog_info
            .clone()
            .into_iter()
            .map(|(id, info)| ListGet200ResponseTasksInner {
                id: Some(id as i32),
                name: Some(format!("{} - {:?}", info.0, info.1)),
            })
            .collect()
    }

    pub async fn stop_prog(
        &mut self,
        id: usize,
        prog_info: (String, ProgramType),
    ) -> Result<StopPostResponse, EcliError> {
        let (prog_name, prog_type) = prog_info;

        match prog_type {
            ProgramType::JsonEunomia => {
                // let task = self.json_tasks.remove(&id);
                // if let Some(t) = task {
                //     if t.stop().await.is_ok() {
                //         return Ok(StopPostResponse::gen_rsp(
                //             format!("{} terminated", &prog_name).as_str(),
                //         ));
                //     };
                // }
                return Ok(StopPostResponse::gen_rsp("fail to terminate"));
            }
            ProgramType::WasmModule => {
                let task = self.wasm_tasks.remove(&id);

                if let Some(t) = task {
                    let handler = t.handler.lock().await;

                    if handler.terminate().is_ok() {
                        self.prog_info.remove(&id);
                        return Ok(StopPostResponse::gen_rsp(
                            format!("{} terminated", &prog_name).as_str(),
                        ));
                    }
                    return Ok(StopPostResponse::gen_rsp("fail to terminate"));
                } else {
                    return Err(EcliError::Other("WasmModule handler notfound".to_string()));
                }
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone)]
pub struct WasmModuleProgram {
    pub handler: Arc<Mutex<WasmProgramHandle>>,

    pub log_msg: LogMsg,
}

impl WasmModuleProgram {
    fn new(handler: WasmProgramHandle, log_msg: LogMsg) -> Self {
        Self {
            handler: Arc::new(Mutex::new(handler)),
            log_msg,
        }
    }
}

#[derive(Clone)]
pub struct JsonEunomiaProgram {
    _ptr: Arc<Mutex<usize>>,

    #[allow(dead_code)]
    log_msg: LogMsg,
}

#[derive(Clone)]
#[allow(unused)]
pub struct LogMsg {
    pub stdout: LogMsgInner,
    pub stderr: LogMsgInner,
}
use std::sync::atomic::AtomicUsize;

#[derive(Clone)]
pub struct LogMsgInner {
    pipe: ReadableWritePipe<Cursor<Vec<u8>>>,
    position: Arc<AtomicUsize>,
}

impl LogMsgInner {
    fn new(pipe: ReadableWritePipe<Cursor<Vec<u8>>>) -> Self {
        Self {
            pipe,
            position: Arc::new(AtomicUsize::new(0)),
        }
    }
}

pub trait LogHandle {
    /// get all log msg
    fn read_log_all(&self) -> Result<String, std::string::FromUtf8Error>;

    /// follow the log
    fn follow_log(&mut self) -> String;
}

use std::sync::atomic::Ordering::SeqCst;

impl LogHandle for LogMsgInner {
    fn read_log_all(&self) -> Result<String, std::string::FromUtf8Error> {
        let log = self.pipe.get_read_lock().get_ref().to_vec();
        String::from_utf8(log)
    }

    fn follow_log(&mut self) -> String {
        let guard = self.pipe.get_read_lock();
        let pos = self.position.clone();

        let vec_ref = guard.get_ref();
        let idx = pos.load(SeqCst);
        if vec_ref.len() > idx {
            let freezed = String::from_utf8(vec_ref[idx..].to_vec()).unwrap();
            self.position
                .fetch_add(vec_ref.len() - idx as usize, SeqCst);
            return freezed;
        }
        String::default()
    }
}

impl LogMsg {
    pub fn new(
        stdout: ReadableWritePipe<Cursor<Vec<u8>>>,
        stderr: ReadableWritePipe<Cursor<Vec<u8>>>,
    ) -> Self {
        Self {
            stdout: LogMsgInner::new(stdout),
            stderr: LogMsgInner::new(stderr),
        }
    }
}

impl StopPostResponse {
    pub fn gen_rsp(status: &str) -> StopPostResponse {
        StopPostResponse::StatusOfStoppingTheTask(StopPost200Response {
            status: Some(status.into()),
        })
    }
}

impl StartPostResponse {
    pub fn gen_rsp(id: i32) -> StartPostResponse {
        StartPostResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("Ok".into()),
            tasks: Some(vec![ListGet200ResponseTasksInner {
                id: Some(id),
                name: None,
            }]),
        })
    }
}
impl ListGetResponse {
    pub fn gen_rsp(tsks: Vec<ListGet200ResponseTasksInner>) -> ListGetResponse {
        ListGetResponse::ListOfRunningTasks(ListGet200Response {
            status: Some("Ok".into()),
            tasks: Some(tsks),
        })
    }
}

impl LogPostResponse {
    pub fn gen_rsp(stdout: Option<String>, stderr: Option<String>) -> LogPostResponse {
        LogPostResponse::SendLog(LogPost200Response { stdout, stderr })
    }
}
