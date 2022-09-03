mod bindings;
mod config;
mod server;
use std::env;

extern crate link_cplusplus;

use bindings::BPFProgram;
use tokio::{fs, time::Instant};
extern crate lazy_static;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        "Running slow_function() took {} seconds.",
        elapsed_time.as_secs()
    );
    Ok(())
}
