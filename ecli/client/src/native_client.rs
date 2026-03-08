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
    runner::{native::NativeRunner, native::RunningProgram, LogEntry, LogType},
};

use crate::helper::load_prog_buf_and_guess_type;

pub static TERMINATED: AtomicBool = AtomicBool::new(false);
const MAX_LOG_BATCHES_PER_TICK: usize = 8;

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
        let drained_all = drain_logs(&program, &mut last_poll, MAX_LOG_BATCHES_PER_TICK);
        if TERMINATED.load(Ordering::Relaxed) {
            break;
        }
        if program.has_exited() {
            drain_all_logs(&program, &mut last_poll);
            break;
        }
        if drained_all {
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
    program.terminate()?;
    Ok(())
}

fn drain_all_logs(program: &RunningProgram, last_poll: &mut Option<usize>) {
    while !drain_logs(program, last_poll, MAX_LOG_BATCHES_PER_TICK) {}
}

fn drain_logs(program: &RunningProgram, last_poll: &mut Option<usize>, max_batches: usize) -> bool {
    drain_logs_with_limit(
        last_poll,
        max_batches,
        |cursor| program.fetch_logs(cursor, None),
        emit_log,
    )
}

fn drain_logs_with_limit<F, G>(
    last_poll: &mut Option<usize>,
    max_batches: usize,
    mut fetch_logs: F,
    mut emit_log: G,
) -> bool
where
    F: FnMut(Option<usize>) -> Vec<(usize, LogEntry)>,
    G: FnMut(LogEntry),
{
    for _ in 0..max_batches {
        let logs = fetch_logs(*last_poll);
        if logs.is_empty() {
            return true;
        }
        for (cursor, log) in logs {
            emit_log(log);
            *last_poll = Some(cursor + 1);
        }
    }
    false
}

fn emit_log(log: LogEntry) {
    if let LogType::Plain = log.log_type {
        println!("{}", log.log);
    } else {
        print!("{}", log.log);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    fn test_log(message: &str) -> LogEntry {
        LogEntry {
            log: message.to_string(),
            timestamp: 0,
            log_type: LogType::Plain,
        }
    }

    #[test]
    fn drain_logs_with_limit_stops_after_the_requested_number_of_batches() {
        let mut batches = VecDeque::from([
            vec![(0, test_log("first"))],
            vec![(1, test_log("second"))],
            vec![(2, test_log("third"))],
        ]);
        let mut emitted = Vec::new();
        let mut last_poll = None;

        let drained_all = drain_logs_with_limit(
            &mut last_poll,
            2,
            |_| batches.pop_front().unwrap_or_default(),
            |log| emitted.push(log.log),
        );

        assert!(!drained_all);
        assert_eq!(emitted, vec!["first", "second"]);
        assert_eq!(last_poll, Some(2));
    }

    #[test]
    fn drain_logs_with_limit_reports_when_no_more_logs_are_available() {
        let mut batches = VecDeque::from([vec![(0, test_log("only"))], Vec::new()]);
        let mut emitted = Vec::new();
        let mut last_poll = None;

        let drained_all = drain_logs_with_limit(
            &mut last_poll,
            MAX_LOG_BATCHES_PER_TICK,
            |_| batches.pop_front().unwrap_or_default(),
            |log| emitted.push(log.log),
        );

        assert!(drained_all);
        assert_eq!(emitted, vec!["only"]);
        assert_eq!(last_poll, Some(1));
    }
}
