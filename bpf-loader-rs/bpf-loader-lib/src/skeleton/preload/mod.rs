use std::collections::HashMap;

use crate::{
    btf_container::BtfContainer,
    meta::{DataSectionMeta, EunomiaObjectMeta, RunnerConfig},
    skeleton::preload::section_loader::load_section_data,
};
use anyhow::{anyhow, bail, Context, Result};
use btf::types::{Btf, BtfType};
use libbpf_rs::OpenObject;

use super::BpfSkeleton;

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
            let map_meta = match section.name.as_str() {
                ".rodata" => self
                    .meta
                    .bpf_skel
                    .find_map_by_ident("rodata")
                    .ok_or_else(|| {
                        anyhow!("Failed to find map with ident rodata for section .rodata")
                    })?,
                ".bss" => self
                    .meta
                    .bpf_skel
                    .find_map_by_ident(".bss")
                    .ok_or_else(|| {
                        anyhow!("Failed to find map with bss rodata for section .bss")
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
            map.set_initial_value(&buffer[..])
                .map_err(|e| anyhow!("Failed to set initial value of map `{}`: {}", map_name, e))?;
        }

        let bpf_object = self
            .bpf_object
            .load()
            .with_context(|| anyhow!("Failed to load bpf object"))?;
        // Next steps are attaching...

        todo!();
    }
}
