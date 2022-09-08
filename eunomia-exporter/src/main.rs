mod bindings;
mod bpfprog;
mod config;
mod server;
mod state;

extern crate link_cplusplus;

use config::ExporterConfig;

extern crate lazy_static;

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = ExporterConfig::from_file("examples/opensnoop/opensnoop.json")?;
    server::start_server(&config)?;
    Ok(())
}
