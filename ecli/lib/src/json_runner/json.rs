//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
<<<<<<<< HEAD:ecli/lib/src/json_runner/json.rs
|||||||| parent of 10743ce (chore: resolve conflict):ecli/src/json_runner/json.rs
use std::ffi::CStr;
========

use std::ffi::CStr;
>>>>>>>> 10743ce (chore: resolve conflict):ecli/ecli-lib/src/json_runner/json.rs
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::ptr::null_mut;

use crate::config::ExportFormatType;
use crate::config::ProgramConfigData;
use crate::error::{EcliError, EcliResult};

<<<<<<<< HEAD:ecli/lib/src/json_runner/json.rs
use crate::eunomia_bpf::{
    export_format_type_EXPORT_JSON, export_format_type_EXPORT_PLANT_TEXT,
    load_and_attach_eunomia_skel, open_eunomia_skel_from_json_package_with_args,
    wait_and_poll_events_to_handler,
};
|||||||| parent of 10743ce (chore: resolve conflict):ecli/src/json_runner/json.rs
use super::eunomia_bpf::export_format_type_EXPORT_JSON;
use super::eunomia_bpf::export_format_type_EXPORT_PLANT_TEXT;
use super::eunomia_bpf::load_and_attach_eunomia_skel;
use super::eunomia_bpf::open_eunomia_skel_from_json_package_with_args;
use super::eunomia_bpf::wait_and_poll_events_to_handler;
========
use crate::eunomia_bpf;

pub use eunomia_bpf::{
    export_format_type_EXPORT_JSON, export_format_type_EXPORT_PLANT_TEXT,
    load_and_attach_eunomia_skel, open_eunomia_skel_from_json_package_with_args,
    parse_args_to_json_config, wait_and_poll_events_to_handler,
};
>>>>>>>> 10743ce (chore: resolve conflict):ecli/ecli-lib/src/json_runner/json.rs

unsafe extern "C" fn handler(
    _ctx: *mut ::std::os::raw::c_void,
    event: *const ::std::os::raw::c_char,
<<<<<<<< HEAD:ecli/lib/src/json_runner/json.rs
    size: crate::eunomia_bpf::size_t,
|||||||| parent of 10743ce (chore: resolve conflict):ecli/src/json_runner/json.rs
    _size: super::eunomia_bpf::size_t,
========
    _size: eunomia_bpf::size_t,
>>>>>>>> 10743ce (chore: resolve conflict):ecli/ecli-lib/src/json_runner/json.rs
) {
    println!(
        "{}",
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(
            event as *const u8,
            size as usize
        ))
    );
}

/// Takes a ProgramConfigData as input and executes an eBPF program using the configuration data provided.
/// The function converts the JSON data into a CString and creates a vector of arguments to pass to the eBPF program.
/// The eBPF program is then loaded and attached, and events are polled and handled using the specified handler function.
pub fn handle_json(conf: ProgramConfigData) -> EcliResult<()> {
    let _ = json_handler(conf);
    Ok(())
}

pub fn json_handler(conf: ProgramConfigData) -> EcliResult<*mut eunomia_bpf::eunomia_bpf> {
    let json_data = CString::new(conf.program_data_buf.as_slice())
        .map_err(|e| EcliError::Other(e.to_string()))?;
    let mut extra_arg_raw = vec![];
    let mut cstr_vec = vec![];
    let arg = CString::new(conf.url.as_bytes()).unwrap();
    extra_arg_raw.push(arg.as_ptr() as *mut c_char);
    for arg in conf.extra_arg {
        cstr_vec.push(CString::new(arg.as_bytes()).unwrap());
        extra_arg_raw.push(cstr_vec.last().unwrap().as_ptr() as *mut c_char);
    }
    let bpf = unsafe {
        open_eunomia_skel_from_json_package_with_args(
            json_data.as_ptr() as *const c_char,
            extra_arg_raw.as_mut_ptr(),
            extra_arg_raw.len() as i32,
            match conf.btf_path {
                Some(path) => path.as_ptr() as *mut c_char,
                _ => std::ptr::null_mut(),
            },
        )
    };
    if bpf.is_null() {
        return Err(EcliError::BpfError("open bpf from json fail".to_string()));
    }

    unsafe {
        if load_and_attach_eunomia_skel(bpf) < 0 {
            return Err(EcliError::BpfError(
                "load and attach ebpf program failed".to_string(),
            ));
        }

        if wait_and_poll_events_to_handler(
            bpf,
            match conf.export_format_type {
                ExportFormatType::ExportJson => export_format_type_EXPORT_JSON,
                ExportFormatType::ExportPlantText => export_format_type_EXPORT_PLANT_TEXT,
            },
            Some(handler),
            null_mut::<c_void>(),
        ) < 0
        {
            return Err(EcliError::BpfError(
                "wait and poll to handler failed".to_string(),
            ));
        }
    }

    Ok(bpf)
}
