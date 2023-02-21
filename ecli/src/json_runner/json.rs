//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::ptr::null_mut;

use crate::config::ExportFormatType;
use crate::config::ProgramConfigData;
use crate::error::EcliError;
use crate::error::EcliResult;

use super::eunomia_bpf::export_format_type_EXPORT_JSON;
use super::eunomia_bpf::export_format_type_EXPORT_PLANT_TEXT;
use super::eunomia_bpf::load_and_attach_eunomia_skel;
use super::eunomia_bpf::open_eunomia_skel_from_json_package_with_args;
use super::eunomia_bpf::wait_and_poll_events_to_handler;

unsafe extern "C" fn handler(
    _ctx: *mut ::std::os::raw::c_void,
    event: *const ::std::os::raw::c_char,
    _size: super::eunomia_bpf::size_t,
) {
    println!("{}", CStr::from_ptr(event).to_string_lossy().to_string());
}

pub fn handle_json(conf: ProgramConfigData) -> EcliResult<()> {
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

    Ok(())
}
