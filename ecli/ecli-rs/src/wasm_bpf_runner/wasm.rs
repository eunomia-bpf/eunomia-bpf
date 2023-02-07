//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    ffi::CString,
    os::raw::{c_char, c_int},
};

use crate::{
    config::ProgramConfigData,
    error::{EcliError, EcliResult},
};

use super::wasm_bpf::{wasm_bpf_start, new_wasm_bpf};

pub fn handle_wasm(mut conf: ProgramConfigData) -> EcliResult<()> {
    unsafe {
        let p = new_wasm_bpf();
        let env = CString::new("").unwrap();

        if wasm_bpf_start(
            p,
            conf.program_data_buf.as_mut_ptr() as *mut c_char,
            conf.program_data_buf.len() as c_int,
            env.into_raw() as *mut c_char,
        ) < 0
        {
            return Err(EcliError::WasmError("start wasm-bpf fail".to_string()));
        }
    }
    Ok(())
}
