mod bindings;
mod config;
mod server;
mod state;
use std::env;

extern crate link_cplusplus;

use bindings::BPFProgram;
use tokio::{fs, time::Instant};
extern crate lazy_static;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = config::ExporterConfig {};

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <json file>", args[0]);
        return Ok(());
    }
    let json_data = fs::read_to_string(&args[1]).await?;
    let now = Instant::now();
    let ebpf_program = BPFProgram::create_ebpf_program(&json_data)?;
    ebpf_program.run()?;
    let elapsed_time = now.elapsed();
    println!(
        "Running slow_function() took {} ms.",
        elapsed_time.as_millis()
    );
    // ebpf_program.wait_and_export()?;
    server::start_server(&config).await?;
    Ok(())
}
