use std::{
    ffi::CString,
    os::raw::{c_char, c_int},
};

use crate::{
    config::ProgramConfigData,
    error::{EcliError, EcliResult},
};

use super::ewasm_bpf::{ewasm_bpf_start, new_ewasm_bpf};

pub fn handle_wasm(mut conf: ProgramConfigData) -> EcliResult<()> {
    unsafe {
        let p = new_ewasm_bpf();
        let env = CString::new("").unwrap();

        if ewasm_bpf_start(
            p,
            conf.program_data_buf.as_mut_ptr() as *mut c_char,
            conf.program_data_buf.len() as c_int,
            env.into_raw() as *mut c_char,
        ) < 0
        {
            return Err(EcliError::WasmError("start ewasm fail".to_string()));
        }
    }
    Ok(())
}
