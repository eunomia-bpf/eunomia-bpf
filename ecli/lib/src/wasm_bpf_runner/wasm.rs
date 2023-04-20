//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use crate::{
    config::ProgramConfigData,
    error::{EcliError, EcliResult},
};

use wasm_bpf_rs::run_wasm_bpf_module;

pub fn handle_wasm(conf: ProgramConfigData) -> EcliResult<()> {
    let config = wasm_bpf_rs::Config {
        callback_export_name: String::from("callback-wrapper"),
        wrapper_module_name: String::from("go-callback"),
        ..Default::default()
    };
    run_wasm_bpf_module(
        conf.program_data_buf.as_slice(),
        conf.extra_arg.as_slice(),
        config,
    )
    .map_err(|e| EcliError::WasmError(e.to_string()))
}
