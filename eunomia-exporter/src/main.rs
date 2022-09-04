mod bindings;
mod config;
mod server;
mod state;
use std::{env, sync::Arc};

extern crate link_cplusplus;

use bindings::BPFProgram;
use tokio::{fs, runtime::Builder, time::Instant};

use crate::state::BPFProgramState;
extern crate lazy_static;

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::ExporterConfig {};

    // ebpf_program.wait_and_export()?;
    server::start_server(&config)?;
    Ok(())
}
