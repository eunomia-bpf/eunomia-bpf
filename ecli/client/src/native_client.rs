//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ecli_lib::{
    config::ProgramType,
    runner::{native::NativeRunner, native::RunningProgram, LogType},
};

use crate::helper::load_prog_buf_and_guess_type;

pub static TERMINATED: AtomicBool = AtomicBool::new(false);

pub(crate) async fn run_native(
    export_json: bool,
    prog: String,
    args: &[String],
    user_prog_type: Option<ProgramType>,
) -> anyhow::Result<()> {
    let (buf, prog_type) = load_prog_buf_and_guess_type(&prog, user_prog_type).await?;

    let program = NativeRunner::start_program(&buf, prog_type, export_json, args, None)?;
    let mut last_poll = None;
    loop {
        print_new_logs(&program, &mut last_poll);
        if TERMINATED.load(Ordering::Relaxed) || program.has_exited() {
            print_new_logs(&program, &mut last_poll);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    program.terminate()?;
    Ok(())
}

fn print_new_logs(program: &RunningProgram, last_poll: &mut Option<usize>) {
    for (cursor, log) in program.fetch_logs(*last_poll, None) {
        if let LogType::Plain = log.log_type {
            println!("{}", log.log);
        } else {
            print!("{}", log.log);
        }
        *last_poll = Some(cursor + 1);
    }
}
