//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::fmt::Display;

/// Some helper functions
pub mod helper;
#[cfg(feature = "native-client")]
pub mod native;

/// A log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub log: String,
    pub timestamp: u64,
    pub log_type: LogType,
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let time = chrono::NaiveDateTime::from_timestamp_micros((self.timestamp * 1000) as _)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        write!(f, "<{}> <{}> {}", time, self.log_type, self.log)
    }
}

/// Type of a piece of log
#[derive(Debug, Clone)]
pub enum LogType {
    Stdout,
    Stderr,
    Plain,
}

impl Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogType::Stdout => write!(f, "STDOUT"),
            LogType::Stderr => write!(f, "STDERR"),
            LogType::Plain => write!(f, "PLAIN"),
        }
    }
}

/// The default number og logs to poll
pub const DEFAULT_MAXIMUM_LOG_ENTRIES: usize = 1000;
