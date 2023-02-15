//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    ffi::CString,
    os::raw::c_char,
};

use crate::{
    config::ProgramConfigData,
    error::{EcliError, EcliResult},
};

use super::wasm_bpf::wasm_main;

pub fn handle_wasm(mut conf: ProgramConfigData) -> EcliResult<()> {
    unsafe {
        let mut extra_arg_raw = vec![];
        let mut cstr_vec = vec![];
        let arg = CString::new(conf.url.as_bytes()).unwrap();
        extra_arg_raw.push(arg.as_ptr() as *mut c_char);
        for arg in conf.extra_arg {
            cstr_vec.push(CString::new(arg.as_bytes()).unwrap());
            extra_arg_raw.push(cstr_vec.last().unwrap().as_ptr() as *mut c_char);
        }
        if wasm_main(
            conf.program_data_buf.as_mut_ptr() as *mut u8,
            conf.program_data_buf.len() as u32,
            extra_arg_raw.len() as i32,
            extra_arg_raw.as_mut_ptr(),
        ) < 0
        {
            return Err(EcliError::WasmError("start wasm-bpf fail".to_string()));
        }
    }
    Ok(())
}