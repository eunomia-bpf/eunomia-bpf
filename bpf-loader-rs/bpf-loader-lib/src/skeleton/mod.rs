//! # BpfSkeleton
//!
//! This is the main module of the bpf-loader
//!
//! It provides interfaces to load a bpf-skeleton from JSON, parse it and verify it, and receive data (ringbuf, perfevent, or map values) from it
//!
//! ## The main structure
//!
//! Three objects are provided to the user, see below.
//!
//! ### `BpfSkeletonBuilder`
//!
//! The builder of PreLoadBpfSkeleton, also the start point that the user should use
//!
//! It accepts the JSON skeleton, verify the definitions along with the BTF info in the program, and open the bpf_object
//!
//! It will build a `PreLoadBpfSkeleton`
//!
//! ### `PreLoadBpfSkeleton`
//!
//! A verified and opened bpf_object
//!
//! It has a method called `load_and_attach`, which will try to load the bpf_object, and attach the bpf programs in it to the corresponding attach points. On success, it will return a BpfSkeleton
//!
//! ### `BpfSkeleton`
//!
//! This is the most important object that the user will use.
//!
//! It provide abilities to polling data from the bpf program (through ringbuf, perfevent, or maps) in a unified interface. See `wait_and_poll_to_handler` for details.
//!
//! Besides, it provide ability to control the polling progress in another thread. You can get a handle using `create_poll_handle`, then pause/resume/terminate the polling function in another thread.
use std::{any::Any, sync::Arc};

use libbpf_rs::{Map, MapType, Object};
use log::warn;

use self::{handle::PollingHandle, preload::attach::AttachLink};
use crate::{
    btf_container::BtfContainer,
    export_event::{EventExporterBuilder, EventHandler, ExportFormatType},
    meta::{EunomiaObjectMeta, MapSampleMeta, RunnerConfig},
};
use anyhow::{anyhow, Context, Result};

const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const BTF_PATH_ENV_NAME: &str = "BTF_FILE_PATH";

pub mod builder;
pub mod handle;
pub(crate) mod poller;
pub mod preload;

#[cfg(test)]
mod tests;
/// Represents a polling-ready bpf skeleton. With you can control the ebpf program and poll from it.
pub struct BpfSkeleton {
    pub(crate) handle: PollingHandle,
    ///   data storage
    /// meta data control the behavior of ebpf program:
    /// eg. types of the eBPF maps and prog, export data types
    pub(crate) meta: EunomiaObjectMeta,
    /// config of eunomia itself,
    /// for how we creating, loading and interacting with the eBPF program
    /// eg. poll maps timeout in ms
    /// Note: this field seems to be never used
    #[allow(unused)]
    pub(crate) config_data: RunnerConfig,

    // exporter: EventExporter,
    /// the btf info of the loaded program
    pub(crate) btf: Arc<BtfContainer>,
    /// the links
    #[allow(unused)]
    pub(crate) links: Vec<AttachLink>,
    pub(crate) prog: Object,
}

impl BpfSkeleton {
    /// Create a poll handle to control the poll progress
    /// You can create multiple ones. All handles have the same ability
    pub fn create_poll_handle(&self) -> PollingHandle {
        self.handle.clone()
    }
    /// Get the name of the loaded program
    pub fn get_program_name(&self) -> &str {
        &self.meta.bpf_skel.obj_name
    }
    /// Get the fd of the provided map
    /// returns None if not found
    pub fn get_map_fd(&self, name: impl AsRef<str>) -> Option<i32> {
        self.prog.map(name).map(|m| m.fd())
    }
    /// Get the fd of the provided program
    /// returns None if not found
    pub fn get_prog_fd(&self, name: impl AsRef<str>) -> Option<i32> {
        self.prog.prog(name).map(|p| p.fd())
    }
    /// @brief auto polling and export the data to user space handler
    /// @details The key of the value is the field name in the export json.
    /// This function will block the current thread and poll
    /// If you want to control the poller, just create a handle using `create_poll_handle` before calling this.
    /// Note: this function will set paused and terminating to false before polling.
    pub fn wait_and_poll_to_handler(
        &self,
        export_format_type: ExportFormatType,
        export_event_handler: Option<Arc<dyn EventHandler>>,
        user_context: Option<Arc<dyn Any>>,
    ) -> Result<()> {
        let exporter_builder = EventExporterBuilder::new().set_export_format(export_format_type);
        let exporter_builder = if let Some(hdl) = export_event_handler {
            exporter_builder.set_export_event_handler(hdl)
        } else {
            exporter_builder
        };
        let exporter_builder = if let Some(user_ctx) = user_context {
            exporter_builder.set_user_context(user_ctx)
        } else {
            exporter_builder
        };
        let mut export_map: Option<(String, ExportMapType)> = None;
        for map_meta in self.meta.bpf_skel.maps.iter() {
            let bpf_map = self
                .prog
                .map(&map_meta.name)
                .ok_or_else(|| anyhow!("Map `{}` not found in bpf program", map_meta.name))?;
            if let Some(sample_meta) = &map_meta.sample {
                set_and_warn_existsing_map(
                    &mut export_map,
                    bpf_map,
                    ExportMapType::Sample(sample_meta),
                );
            } else if let MapType::RingBuf = bpf_map.map_type() {
                set_and_warn_existsing_map(&mut export_map, bpf_map, ExportMapType::RingBuffer);
            } else if let MapType::PerfEventArray = bpf_map.map_type() {
                set_and_warn_existsing_map(&mut export_map, bpf_map, ExportMapType::PerfEventArray);
            }
        }
        // Before polling, we should reset the control flags
        self.handle.reset();
        if let Some((map_name, export_type)) = export_map {
            let map = self
                .prog
                .map(&map_name)
                .ok_or_else(|| anyhow!("Invalid map name: {}", map_name))?;
            match export_type {
                ExportMapType::RingBuffer => {
                    let exporter = exporter_builder
                        .build_for_ringbuf(&self.meta.export_types, self.btf.clone())
                        .with_context(|| anyhow!("Failed to build ringbuf exporter"))?;
                    self.wait_and_poll_from_ringbuf(map, exporter)
                        .with_context(|| anyhow!("Failed to poll ringbuf"))?;
                }
                ExportMapType::PerfEventArray => {
                    let exporter = exporter_builder
                        .build_for_ringbuf(&self.meta.export_types, self.btf.clone())
                        .with_context(|| anyhow!("Failed to build perf event exporter"))?;
                    self.wait_and_poll_from_perf_event_array(map, exporter)
                        .with_context(|| anyhow!("Failed to poll perf event"))?;
                }
                ExportMapType::Sample(sample_meta) => {
                    let map_info = map
                        .info()
                        .with_context(|| anyhow!("Failed to get map info for `{}`", map.name()))?;

                    let exporter = exporter_builder
                        .build_for_map_sampling(
                            map_info.info.btf_key_type_id,
                            map_info.info.btf_value_type_id,
                            sample_meta,
                            &self.meta.export_types,
                            self.btf.clone(),
                        )
                        .with_context(|| {
                            anyhow!("Failed to build sampling exporter for `{}`", map.name())
                        })?;
                    self.wait_and_sample_map(map, exporter, sample_meta)
                        .with_context(|| anyhow!("Failed to poll sampling maps"))?;
                }
            };
        } else {
            self.wait_for_no_export_program()
                .with_context(|| anyhow!("Failed to wait for program"))?;
        };
        Ok(())
    }
}

fn set_and_warn_existsing_map<'a>(
    export_map: &mut Option<(String, ExportMapType<'a>)>,
    curr_map: &Map,
    ty: ExportMapType<'a>,
) {
    if let Some((name, _)) = export_map {
        warn!(
            "Multiple export maps found, one is `{}`, another is `{}`",
            name,
            curr_map.name()
        );
    }
    export_map.replace((curr_map.name().into(), ty));
}
enum ExportMapType<'a> {
    RingBuffer,
    PerfEventArray,
    Sample(&'a MapSampleMeta),
}
