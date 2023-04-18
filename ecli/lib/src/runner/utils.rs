//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::config::ExportFormatType;
use crate::config::ProgramConfigData;
use crate::config::ProgramType;
use crate::error::EcliError;
use crate::runner::models::ListGet200Response;
use crate::runner::models::ListGet200ResponseTasksInner;
use crate::runner::models::LogPost200Response;
use crate::runner::models::StopPost200Response;
use crate::runner::EcliResult;
use crate::runner::ListGetResponse;
use crate::runner::LogPostResponse;
use crate::runner::StartPostResponse;
use crate::runner::StopPostResponse;
use crate::EcliResult;
use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Responder;
use eunomia_rs::TempDir;
use swagger::ApiError;
use wasm_bpf_rs::handle::WasmProgramHandle;
use wasm_bpf_rs::pipe::ReadableWritePipe;
use wasm_bpf_rs::run_wasm_bpf_module_async;
use wasm_bpf_rs::Config;

use crate::eunomia_bpf::{destroy_eunomia_skel, eunomia_bpf};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::{collections::HashMap, fs::write};
use std::{io::Cursor, sync::Arc};
use tokio::sync::Mutex;

use super::server::StartReq;

#[derive(Clone)]
pub struct Server<C> {
    pub data: Arc<Mutex<ServerData>>,
    pub marker: PhantomData<C>,
}

#[derive(Clone)]
pub struct ServerData {
    pub wasm_tasks: HashMap<usize, WasmModuleProgram>,
    pub json_tasks: HashMap<usize, JsonEunomiaProgram>,
    pub prog_info: HashMap<usize, (String, ProgramType)>,
    pub global_count: usize,
}

struct EunomiaBpfPtr(NonNull<eunomia_bpf>);

unsafe impl Send for EunomiaBpfPtr {}
unsafe impl Sync for EunomiaBpfPtr {}

impl Drop for EunomiaBpfPtr {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

impl EunomiaBpfPtr {
    #[allow(unused)]
    fn from_raw_ptr(p: *mut eunomia_bpf) -> Self {
        let ptr = NonNull::<eunomia_bpf>::new(p).expect("ptr of `eunomia_bpf` is null!");
        Self(ptr)
    }

    fn get_raw(&mut self) -> *mut eunomia_bpf {
        NonNull::as_ptr(self.0)
    }

    fn terminate(&mut self) -> EcliResult<()> {
        unsafe { destroy_eunomia_skel(self.get_raw()) }
        Ok(())
    }
}
pub struct StartupElements<'a> {
    program_name: String,
    program_data_buf: Vec<u8>,
    extra_params: &'a Vec<String>,
}
impl<'a> StartupElements<'a> {
    pub fn new(
        program_name: Option<String>,
        program_data_buf: Option<swagger::ByteArray>,
        extra_params: Option<&'a Vec<String>>,
    ) -> Self {
        let elements = Self {
            program_name: program_name.unwrap_or_else(|| "NamelessProg".to_string()),
            program_data_buf: program_data_buf.unwrap().0,
            extra_params: extra_params.unwrap(),
        };

        return elements;
    }

    fn _validate(&self) -> EcliResult<()> {
        match *self.program_data_buf {
            _ => Ok(()),
        }
    }
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
        let crate::runner::StartReq {
            program_name,
            program_data_buf,
            extra_params,
            ..
        } = startup_elem;

        let id = self.global_count;

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

        self.global_count += 1;

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
        let id = self.global_count;

        let _data = ProgramConfigData {
            url: String::default(),
            use_cache: false,
            btf_path: None,
            program_data_buf: program_data_buf.unwrap().as_slice().to_owned(),
            extra_arg: extra_params.unwrap(),
            prog_type: ProgramType::JsonEunomia,
            export_format_type: ExportFormatType::ExportPlantText,
        };

        // let stdout = ReadableWritePipe::new_vec_buf();
        // let stderr = ReadableWritePipe::new_vec_buf();
        // let ptr = EunomiaBpfPtr::from_raw_ptr(json_runner::handle_json(data).unwrap());
        // let prog = JsonEunomiaProgram::new(ptr, LogMsg::new(stdout, stderr));
        // self.json_tasks.insert(id, prog);
        // self.prog_info
        //     .insert(id, (program_name, ProgramType::JsonEunomia));

        self.global_count += 1;
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

        let id = self.global_count;
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
            global_count: 0,
        }
    }

    pub fn get_type_of(&self, id: usize) -> Option<ProgramType> {
        self.prog_info.get(&id).map(|v| v.1.clone())
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
        id: i32,
        prog_info: (String, ProgramType),
    ) -> Result<StopPostResponse, EcliError> {
        let (prog_name, prog_type) = prog_info;

        match prog_type {
            ProgramType::JsonEunomia => {
                let task = self
                    .json_tasks
                    .remove(&(id.checked_abs().unwrap() as usize));
                if let Some(t) = task {
                    if t.stop().await.is_ok() {
                        return Ok(StopPostResponse::gen_rsp(
                            format!("{} terminated", &prog_name).as_str(),
                        ));
                    };
                }
                return Ok(StopPostResponse::gen_rsp("fail to terminate"));
            }
            ProgramType::WasmModule => {
                let task = self
                    .wasm_tasks
                    .remove(&(id.checked_abs().unwrap() as usize));

                if let Some(t) = task {
                    let handler = t.handler.lock().await;

                    if handler.terminate().is_ok() {
                        self.prog_info.remove(&(id.checked_abs().unwrap() as usize));
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

    #[allow(dead_code)]
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
    ptr: Arc<Mutex<EunomiaBpfPtr>>,

    #[allow(dead_code)]
    log_msg: LogMsg,
}

impl JsonEunomiaProgram {
    #[allow(unused)]
    fn new(ptr: EunomiaBpfPtr, log_msg: LogMsg) -> Self {
        Self {
            ptr: Arc::new(Mutex::new(ptr)),
            log_msg,
        }
    }
    // TODO: ?

    async fn stop(self) -> EcliResult<()> {
        self.ptr.lock_owned().await.terminate()
    }
}

#[derive(Clone)]
#[allow(unused)]
pub struct LogMsg {
    stdout: LogMsgInner,
    stderr: LogMsgInner,
}

macro_rules! impl_log_method {
    ($n: ident, $l:ident) => {
        impl LogMsg {
            pub fn $n(&mut self) -> String {
                let guard = self.$l.pipe.get_read_lock();
                let read_len = self.$l.read_length;

                let vec_ref = guard.get_ref();

                if vec_ref.len() > read_len {
                    let freezed = String::from_utf8(vec_ref[read_len..].to_vec()).unwrap();
                    self.$l.read_length = vec_ref.len();
                    return freezed;
                } else {
                    return String::default();
                };
            }
        }
    };
}

impl_log_method!(get_stdout, stdout);
impl_log_method!(get_stderr, stderr);

#[derive(Clone)]
struct LogMsgInner {
    pipe: ReadableWritePipe<Cursor<Vec<u8>>>,
    // TODO: multi connection?
    read_length: usize,
}

impl LogMsg {
    pub fn new(
        stdout: ReadableWritePipe<Cursor<Vec<u8>>>,
        stderr: ReadableWritePipe<Cursor<Vec<u8>>>,
    ) -> Self {
        Self {
            stdout: LogMsgInner {
                pipe: stdout,
                read_length: 0,
            },
            stderr: LogMsgInner {
                pipe: stderr,
                read_length: 0,
            },
        }
    }
}

impl<C> Server<C> {
    pub fn new(data: Arc<Mutex<ServerData>>) -> Self {
        Server {
            data,
            marker: PhantomData,
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

macro_rules! impl_responder {
    ($n: ident) => {
        impl Responder for $n {
            type Body = BoxBody;

            fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
                let body = serde_json::to_string(&self).unwrap();

                // Create response and set content type
                HttpResponse::Ok()
                    .content_type(ContentType::json())
                    .body(body)
            }
        }
    };
}

impl_responder!(StartPostResponse);
impl_responder!(StopPostResponse);
impl_responder!(ListGetResponse);
impl_responder!(LogPostResponse);
