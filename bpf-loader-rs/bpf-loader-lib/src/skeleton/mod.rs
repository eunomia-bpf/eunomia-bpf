//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

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
use log::{debug, warn};

use self::{handle::PollingHandle, poller::Poller, preload::attach::AttachLink};
use crate::{
    btf_container::BtfContainer,
    export_event::{
        type_descriptor::TypeDescriptor, EventExporter, EventExporterBuilder, EventHandler,
        ExportFormatType,
    },
    meta::{EunomiaObjectMeta, MapExportConfig, MapMeta, MapSampleMeta, RunnerConfig},
    program_poll_loop,
};
use anyhow::{anyhow, bail, Context, Result};

const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const BTF_PATH_ENV_NAME: &str = "BTF_FILE_PATH";

/// The builder of the skeleton
pub mod builder;
/// controlling handles
pub mod handle;
pub(crate) mod poller;
/// The preloaded skeleton
pub mod preload;

#[cfg(test)]
#[cfg(not(feature = "no-load-bpf-tests"))]
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

    fn build_poller_from_exporter<'a>(
        &self,
        exporter: Arc<EventExporter>,
        export_type: ExportMapType<'a>,
        bpf_map: &'a Map,
    ) -> Result<Poller<'a>> {
        let ret = match export_type {
            ExportMapType::RingBuffer => Poller::RingBuf(
                self.build_ringbuf_poller(bpf_map, exporter)
                    .with_context(|| anyhow!("Failed to build ringbuf poller"))?,
            ),
            ExportMapType::PerfEventArray => Poller::PerfEvent(
                self.build_perfevent_poller(bpf_map, exporter)
                    .with_context(|| anyhow!("Failed to builf perfevent poller"))?,
            ),
            ExportMapType::Sample(sp) => Poller::SampleMap(
                self.build_sample_map_poller(bpf_map, exporter, sp)
                    .with_context(|| anyhow!("Failed to build sample map poller"))?,
            ),
        };
        Ok(ret)
    }

    fn wait_and_poll_with_old_single_export(
        &self,
        export_format_type: ExportFormatType,
        export_event_handler: Option<Arc<dyn EventHandler>>,
        user_context: Option<Arc<dyn Any>>,
    ) -> Result<()> {
        let mut export_map: Option<(&MapMeta, ExportMapType)> = None;
        for map_meta in self.meta.bpf_skel.maps.iter() {
            let bpf_map = self
                .prog
                .map(&map_meta.name)
                .ok_or_else(|| anyhow!("Map `{}` not found in bpf program", map_meta.name))?;
            if let Some(sample_meta) = &map_meta.sample {
                set_and_warn_existsing_map(
                    &mut export_map,
                    map_meta,
                    ExportMapType::Sample(sample_meta),
                );
            } else if let MapType::RingBuf = bpf_map.map_type() {
                set_and_warn_existsing_map(&mut export_map, map_meta, ExportMapType::RingBuffer);
            } else if let MapType::PerfEventArray = bpf_map.map_type() {
                set_and_warn_existsing_map(
                    &mut export_map,
                    map_meta,
                    ExportMapType::PerfEventArray,
                );
            }
        }
        if let Some((map_meta, export_type)) = export_map {
            let bpf_map = self
                .prog
                .map(&map_meta.name)
                .ok_or_else(|| anyhow!("Invalid map name: {}", map_meta.name))?;
            let exporter_builder =
                create_exporter_builder(export_format_type, export_event_handler, user_context);
            if self.meta.export_types.is_empty() {
                bail!(
                    "Export map named `{}` found, but no export type is provided",
                    map_meta.name
                );
            }
            let exporter = match export_type {
                ExportMapType::RingBuffer => exporter_builder
                    .build_for_single_value(&self.meta.export_types[0], self.btf.clone())?,
                ExportMapType::PerfEventArray => exporter_builder
                    .build_for_single_value(&self.meta.export_types[0], self.btf.clone())?,
                ExportMapType::Sample(sp) => {
                    let map_info = bpf_map.info().with_context(|| {
                        anyhow!("Failed to get map info for `{}`", bpf_map.name())
                    })?;
                    exporter_builder.build_for_key_value(
                        map_info.info.btf_key_type_id,
                        map_info.info.btf_value_type_id,
                        sp,
                        &self.meta.export_types[0],
                        self.btf.clone(),
                    )?
                }
            };
            let poller = self.build_poller_from_exporter(exporter, export_type, bpf_map)?;
            self.handle.reset();
            program_poll_loop!(&self.handle, {
                poller.poll()?;
            });
        } else {
            self.wait_for_no_export_program()
                .with_context(|| anyhow!("Failed to wait for program"))?;
        }
        Ok(())
    }
    /// Start poll with each map corresponding to a different exporter
    /// The function `exporter_provider` should return the ExportFormatType, EventHandler, and UserContext(if applies) for the given map name (If you want to set the exporter)
    pub fn wait_and_poll_to_handler_with_multiple_exporter(
        &self,
        exporter_provider: impl Fn(
            &str,
        ) -> Option<(
            ExportFormatType,
            Arc<dyn EventHandler>,
            Option<Arc<dyn Any>>,
        )>,
    ) -> Result<()> {
        if !self.meta.enable_multiple_export_types {
            bail!("This function only supports multiple export types");
        }
        let mut export_maps: Vec<(&MapMeta, ExportMapType)> = vec![];
        for map_meta in self
            .meta
            .bpf_skel
            .maps
            .iter()
            .filter(|v| !matches!(v.export_config, MapExportConfig::NoExport))
        {
            let bpf_map = self
                .prog
                .map(&map_meta.name)
                .ok_or_else(|| anyhow!("Map `{}` not found in bpf program", map_meta.name))?;
            if let Some(sample_meta) = &map_meta.sample {
                export_maps.push((map_meta, ExportMapType::Sample(sample_meta)))
            } else {
                match bpf_map.map_type() {
                    MapType::RingBuf => export_maps.push((map_meta, ExportMapType::RingBuffer)),
                    MapType::PerfEventArray => {
                        export_maps.push((map_meta, ExportMapType::PerfEventArray))
                    }
                    _ => {
                        debug!(
                            "Ignore map named {}, it's neither ringbuf nor perf event",
                            map_meta.name
                        )
                    }
                }
            }
        }
        debug!("Export maps: {:#?}", export_maps);

        // Before polling, we should reset the control flags
        self.handle.reset();
        if export_maps.is_empty() {
            self.wait_for_no_export_program()
                .with_context(|| anyhow!("Failed to wait for a non-export program"))?;
        } else {
            let mut pollers = vec![];
            for (map_meta, export_map_type) in export_maps.into_iter() {
                let bpf_map = self
                    .prog
                    .map(&map_meta.name)
                    .ok_or_else(|| anyhow!("Invalid map name: {}", map_meta.name))?;
                let map_info = bpf_map
                    .info()
                    .with_context(|| anyhow!("Failed to get map info for `{}`", bpf_map.name()))?;
                let is_sample_map = matches!(export_map_type, ExportMapType::Sample(_));
                // Fetch the export type, at here.
                let type_desc = match &map_meta.export_config {
                    MapExportConfig::ExportUseBtf(ty_id) => {
                        TypeDescriptor::BtfType { type_id: *ty_id }
                    }
                    MapExportConfig::ExportUseCustomMembers(mems) => {
                        TypeDescriptor::ManuallyOverride(mems.clone())
                    }
                    MapExportConfig::Default => {
                        if is_sample_map {
                            TypeDescriptor::BtfType {
                                type_id: map_info.info.btf_value_type_id,
                            }
                        } else {
                            bail!("MapExportConfig::Default only applies to sample map");
                        }
                    }
                    MapExportConfig::NoExport => unreachable!("How could you reach here?"),
                };
                let builder = EventExporterBuilder::new();
                let builder = if let Some((ty, handler, ctx)) = exporter_provider(&map_meta.name) {
                    builder
                        .set_export_format(ty)
                        .set_export_event_handler(handler)
                        .set_user_context(ctx)
                } else {
                    builder
                };
                match export_map_type {
                    ExportMapType::RingBuffer => {
                        let exporter = builder
                            .build_for_single_value_with_type_descriptor(
                                type_desc,
                                self.btf.clone(),
                            )
                            .with_context(|| anyhow!("Failed to build ringbuf exporter"))?;
                        pollers.push(Poller::RingBuf(
                            self.build_ringbuf_poller(bpf_map, exporter)?,
                        ));
                    }
                    ExportMapType::PerfEventArray => {
                        let exporter = builder
                            .build_for_single_value_with_type_descriptor(
                                type_desc,
                                self.btf.clone(),
                            )
                            .with_context(|| anyhow!("Failed to build perf event exporter"))?;
                        pollers.push(Poller::PerfEvent(
                            self.build_perfevent_poller(bpf_map, exporter)?,
                        ));
                    }
                    ExportMapType::Sample(cfg) => {
                        let exporter = builder
                            .build_for_key_value_with_type_desc(
                                TypeDescriptor::BtfType {
                                    type_id: map_info.info.btf_key_type_id,
                                },
                                type_desc,
                                cfg,
                                self.btf.clone(),
                            )
                            .with_context(|| {
                                anyhow!(
                                    "Failed to build sampling exporter for `{}`",
                                    bpf_map.name()
                                )
                            })?;
                        pollers.push(Poller::SampleMap(
                            self.build_sample_map_poller(bpf_map, exporter, cfg)?,
                        ));
                    }
                }
            }
            program_poll_loop!(&self.handle, {
                for poller in pollers.iter() {
                    poller.poll()?;
                }
            });
        }
        Ok(())
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
        if !self.meta.enable_multiple_export_types {
            return self.wait_and_poll_with_old_single_export(
                export_format_type,
                export_event_handler,
                user_context,
            );
        }
        self.wait_and_poll_to_handler_with_multiple_exporter(|_| {
            export_event_handler
                .clone()
                .map(|v| (export_format_type, v, user_context.clone()))
        })
    }
}

fn set_and_warn_existsing_map<'a>(
    export_map: &mut Option<(&'a MapMeta, ExportMapType<'a>)>,
    curr_map: &'a MapMeta,
    ty: ExportMapType<'a>,
) {
    if let Some((meta, _)) = export_map {
        warn!(
            "Multiple export maps found, one is `{}`, another is `{}`",
            meta.name, curr_map.name
        );
    }
    export_map.replace((curr_map, ty));
}
#[derive(Debug)]
enum ExportMapType<'a> {
    RingBuffer,
    PerfEventArray,
    Sample(&'a MapSampleMeta),
}

fn create_exporter_builder(
    export_format: ExportFormatType,
    event_handler: Option<Arc<dyn EventHandler>>,
    ctx: Option<Arc<dyn Any>>,
) -> EventExporterBuilder {
    let exporter_builder = EventExporterBuilder::new().set_export_format(export_format);
    let exporter_builder = if let Some(hdl) = event_handler.clone() {
        exporter_builder.set_export_event_handler(hdl)
    } else {
        exporter_builder
    };

    if let Some(user_ctx) = ctx.clone() {
        exporter_builder.set_user_context(user_ctx)
    } else {
        exporter_builder
    }
}
