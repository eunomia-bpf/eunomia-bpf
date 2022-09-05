mod bindings;
mod config;
mod server;
mod state;
mod bpfprog;

extern crate link_cplusplus;

use config::ExporterConfig;

extern crate lazy_static;

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = ExporterConfig::default();

    // ebpf_program.wait_and_export()?;
    server::start_server(&config)?;
    Ok(())
}
