//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::Program;
use log::debug;

use crate::meta::ProgMeta;

use super::AttachLink;

fn init_perf_monitor(freq: u64) -> Result<Vec<i32>> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();

    let mut attrs = perf_event_open_sys::bindings::perf_event_attr::default();
    attrs.size = std::mem::size_of::<perf_event_open_sys::bindings::perf_event_attr>() as u32;
    attrs.type_ = perf_event_open_sys::bindings::PERF_TYPE_HARDWARE;
    attrs.config = perf_event_open_sys::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
    attrs.set_freq(freq);

    let mut pefds = vec![];
    for cpu in 0..nprocs {
        // SAFETY: attrs is valid during the call
        let pefd =
            unsafe { perf_event_open_sys::perf_event_open(&mut attrs, 0, cpu as i32, -1, 0) };
        if pefd < 0 {
            bail!("Failed to call `perf_event_open`");
        }
        pefds.push(pefd);
    }
    Ok(pefds)
}

pub(crate) fn attach_perf_event(
    program: &mut Program,
    _meta: &ProgMeta,
) -> Result<Vec<AttachLink>> {
    debug!("Attaching perf event: {:?}", program);

    let pefds = init_perf_monitor(0).with_context(|| anyhow!("Failed to init perf monitor"))?;

    let mut links = vec![];
    for pefd in pefds.iter() {
        links.push(AttachLink::BpfLink(
            program.attach_perf_event(*pefd).unwrap(),
        ))
    }
    Ok(links)
}
