//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{collections::HashMap, sync::Arc};

use crate::{
    btf_container::BtfContainer,
    meta::{EunomiaObjectMeta, RunnerConfig},
    skeleton::preload::{
        attach::{attach_tc, AttachLink},
        section_loader::load_section_data,
    },
};
use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::OpenObject;
use log::debug;

use super::{handle::PollingHandle, BpfSkeleton};
pub(crate) mod attach;
pub(crate) mod section_loader;
/// Represents an initialized bpf skeleton. It's waiting for the loading and attaching of bpf programs
pub struct PreLoadBpfSkeleton {
    ///   data storage
    /// meta data control the behavior of ebpf program:
    /// eg. types of the eBPF maps and prog, export data types
    pub(crate) meta: EunomiaObjectMeta,
    /// config of eunomia itself,
    /// for how we creating, loading and interacting with the eBPF program
    /// eg. poll maps timeout in ms
    pub(crate) config_data: RunnerConfig,

    pub(crate) bpf_object: OpenObject,

    // Btf for the loaded program
    pub(crate) btf: BtfContainer,

    // Value sizes of maps this program hold
    // This is a workaround for libbpf-rs not exposing bpf_map* in OpenMap
    pub(crate) map_value_sizes: HashMap<String, u32>,
}

impl PreLoadBpfSkeleton {
    /// start running the ebpf program

    /// load and attach the ebpf program to the kernel to run the ebpf program
    /// if the ebpf program has maps to export to user space, you need to call
    /// the wait and export.
    pub fn load_and_attach(mut self) -> Result<BpfSkeleton> {
        // This function differs from the C++ version `int bpf_skeleton::load_and_attach_prog(void)`
        // Because we put the call to bpf_object_open in `BpfSkeletonBuilder::build`
        // So Here are just the calls to load and attach

        // Initialize data for sections
        for section in self.meta.bpf_skel.data_sections.iter() {
            debug!("Loading section: {:?}", section);
            let map_meta = match section.name.as_str() {
                ".rodata" => self
                    .meta
                    .bpf_skel
                    .find_map_by_ident("rodata")
                    .ok_or_else(|| {
                        anyhow!("Failed to find map with ident `rodata` for section .rodata")
                    })?,
                ".bss" => self.meta.bpf_skel.find_map_by_ident("bss").ok_or_else(|| {
                    anyhow!("Failed to find map with ident `bss` for section .bss")
                })?,
                s => bail!("Unsupported section: {}", s),
            };
            let map_name = map_meta.name.as_str();
            let map = self.bpf_object.map_mut(map_name).ok_or_else(|| {
                anyhow!(
                    "Map named `{}` doesn't exist, cannot map section `{}`",
                    map_name,
                    section.name
                )
            })?;
            // Set a buffer to hold the data
            let buffer_size = *self
                .map_value_sizes
                .get(map_name)
                .ok_or_else(|| anyhow!("Map name {} not found in value sizes", map_name))?
                as usize;

            let mut buffer = vec![0; buffer_size];
            load_section_data(self.btf.borrow_btf(), section, &mut buffer)
                .with_context(|| anyhow!("Failed to load section {}", section.name))?;
            debug!("Loaded buffer: {:?}", buffer);
            map.set_initial_value(&buffer[..])
                .map_err(|e| anyhow!("Failed to set initial value of map `{}`: {}", map_name, e))?;
        }

        let mut bpf_object = self
            .bpf_object
            .load()
            .with_context(|| anyhow!("Failed to load bpf object"))?;
        // Next steps are attaching...
        let mut not_attached = vec![];
        let mut links = vec![];
        for prog_meta in self.meta.bpf_skel.progs.iter() {
            let bpf_prog = bpf_object
                .prog_mut(&prog_meta.name)
                .ok_or_else(|| anyhow!("Program named `{}` not found in libbpf", prog_meta.name))?;
            match bpf_prog.attach() {
                Ok(link) => links.push(AttachLink::BpfLink(link)),
                // EOPNOTSUPP 95 Operation not supported
                Err(_) if errno::errno().0 == 95 => {
                    // Not supported for auto-attaching, needs manually operations
                    not_attached.push(prog_meta);
                    continue;
                }
                Err(err) => bail!("Failed to attach program `{}`: {}", prog_meta.name, err),
            };
        }
        for prog_meta in not_attached.into_iter() {
            let bpf_prog = bpf_object
                .prog_mut(&prog_meta.name)
                .ok_or_else(|| anyhow!("Program named `{}` not found", prog_meta.name))?;
            match bpf_prog.section() {
                "tc" => links.push(attach_tc(bpf_prog, prog_meta).with_context(|| {
                    anyhow!("Failed to attach tc program `{}`", prog_meta.name)
                })?),
                s => bail!("Unsupported attach type: {}", s),
            }
        }
        Ok(BpfSkeleton {
            handle: PollingHandle::new(),
            meta: self.meta,
            config_data: self.config_data,
            btf: Arc::new(self.btf),
            links,
            prog: bpf_object,
        })
    }
}

#[cfg(test)]
#[cfg(not(feature = "no-load-bpf-tests"))]
mod tests {
    use crate::{
        meta::ComposedObject, skeleton::builder::BpfSkeletonBuilder, tests::get_assets_dir,
    };

    #[test]
    fn test_load_and_attach() {
        let skel: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(get_assets_dir().join("bootstrap.json")).unwrap(),
        )
        .unwrap();
        let pre_load_skel = BpfSkeletonBuilder::from_json_package(&skel, None)
            .build()
            .unwrap();
        let loaded = pre_load_skel.load_and_attach().unwrap();
        let prog = loaded.prog;
        for map_meta in skel.meta.bpf_skel.maps.iter() {
            let _map_bpf = prog.map(map_meta.name.as_str()).unwrap();
        }
        for prog_meta in skel.meta.bpf_skel.progs.iter() {
            let prog_bpf = prog.prog(&prog_meta.name).unwrap();
            assert_eq!(prog_bpf.section(), prog_meta.attach);
        }
        assert_eq!(loaded.links.len(), skel.meta.bpf_skel.progs.len());
    }
}
