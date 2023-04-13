//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

/// A container to hold self-reference stuff
pub mod btf_container;
/// The event exporter
pub mod export_event;
/// Some helper functions
pub mod helper;
/// Skeleton data types
pub mod meta;
/// The skeleton itself
pub mod skeleton;

/// Re-export clap
pub use clap;
/// Re-export serde
pub use serde;
/// Re-export serde_json
pub use serde_json;
#[cfg(test)]
mod tests;
