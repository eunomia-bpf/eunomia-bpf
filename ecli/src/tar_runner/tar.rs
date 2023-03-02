//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::ptr::null_mut;
use tar::Archive;

use super::eunomia_bpf::export_format_type_EXPORT_JSON;
use super::eunomia_bpf::export_format_type_EXPORT_PLANT_TEXT;
use super::eunomia_bpf::load_and_attach_eunomia_skel;
use super::eunomia_bpf::open_eunomia_skel_from_path;
use super::eunomia_bpf::size_t;
use super::eunomia_bpf::wait_and_poll_events_to_handler;
use eunomia_rs::TempDir;

use crate::config::ExportFormatType;
use crate::config::ProgramConfigData;
use crate::error::EcliError;
use crate::error::EcliResult;

#[repr(C)]
pub struct CHashMap {
    pub keys: *mut *mut c_char,
    pub values: *mut *mut c_void,
    pub len: usize,
}

#[no_mangle]
pub unsafe extern "C" fn to_cpp_map(rust_map: *mut HashMap<PathBuf, Vec<u8>>) -> CHashMap {
    let map = &*rust_map;
    let mut c_keys = Vec::with_capacity(map.len());
    let mut c_values = Vec::with_capacity(map.len());

    for (key, value) in map.iter() {
        let c_str = CString::new(key.to_str().unwrap().as_bytes()).unwrap();
        let c_value = value.as_ptr() as *mut c_void;
        c_keys.push(c_str.into_raw());
        c_values.push(c_value);
    }

    CHashMap {
        keys: c_keys.as_mut_ptr(),
        values: c_values.as_mut_ptr(),
        len: map.len(),
    }
}

unsafe extern "C" fn handler(
    _ctx: *mut ::std::os::raw::c_void,
    event: *const ::std::os::raw::c_char,
    _size: super::eunomia_bpf::size_t,
) {
    println!("{}", CStr::from_ptr(event).to_string_lossy().to_string());
}

pub fn handle_tar(conf: ProgramConfigData) -> EcliResult<()> {
    let tar_data = conf.program_data_buf.as_slice();
    let mut archive = Archive::new(tar_data);

    let tmpdir = TempDir::new().unwrap();
    let tmpdir_path = tmpdir.path();
    let mut bpf_object_buffer = Vec::new();

    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap();
        if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with("bpf.o")
        {
            entry.read_to_end(&mut bpf_object_buffer).unwrap();
            break;
        }
    }

    archive.unpack(tmpdir_path).unwrap();

    let bpf = unsafe {
        open_eunomia_skel_from_path(
            tmpdir_path.to_str().unwrap().as_ptr() as *const c_char,
            bpf_object_buffer.as_ptr() as *const c_char,
            bpf_object_buffer.len() as size_t,
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
