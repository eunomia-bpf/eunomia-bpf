use std::path::PathBuf;

use crate::{
    export_event::EventExporter,
    meta::{EunomiaObjectMeta, RunnerConfig},
};

const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const BTF_PATH_ENV_NAME: &str = "BTF_FILE_PATH";

pub mod builder;
pub mod preload;

/// Represents a polling-ready bpf skeleton. With you can control the ebpf program and poll from it.
pub struct BpfSkeleton {
    /// is the polling ring buffer loop exiting?
    exiting: std::sync::Mutex<bool>,
    ///   data storage
    /// meta data control the behavior of ebpf program:
    /// eg. types of the eBPF maps and prog, export data types
    meta: EunomiaObjectMeta,
    /// config of eunomia itself,
    /// for how we creating, loading and interacting with the eBPF program
    /// eg. poll maps timeout in ms
    config_data: RunnerConfig,

    exporter: EventExporter,
    // The bpf program buffer
    prog: Vec<u8>,
    // The custom btf file
    custom_btf_file: Option<PathBuf>,
}
