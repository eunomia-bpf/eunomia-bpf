//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ecli_lib::{
    config::ProgramType,
    runner::{
        client::{native::EcliNativeClient, AbstractClient},
        LogType,
    },
};

use crate::helper::load_prog_buf_and_guess_type;

pub static TERMINATED: AtomicBool = AtomicBool::new(false);

pub(crate) async fn run_native(
    export_json: bool,
    prog: String,
    args: &[String],
    user_prog_type: Option<ProgramType>,
) -> anyhow::Result<()> {
    let client = EcliNativeClient::default();
    let (buf, prog_type) = load_prog_buf_and_guess_type(&prog, user_prog_type).await?;

    let handle = client
        .start_program(
            Some("NativeProgram".to_string()),
            &buf,
            prog_type,
            export_json,
            args,
            None,
        )
        .await?;
    let mut last_poll = None;
    loop {
        let logs = client.fetch_logs(handle, last_poll, None).await?;
        for (cursor, log) in logs.into_iter() {
            if let LogType::Plain = log.log_type {
                println!("{}", log.log);
            } else {
                print!("{}", log.log);
            }
            last_poll = Some(cursor + 1);
        }
        if TERMINATED.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    client.terminate_program(handle).await?;
    Ok(())
}
