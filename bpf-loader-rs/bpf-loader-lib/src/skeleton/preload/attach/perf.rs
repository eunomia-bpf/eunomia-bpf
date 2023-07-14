//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::Program;
use log::debug;
use perf_event_open_sys::{
    bindings::{
        perf_event_attr, perf_event_attr__bindgen_ty_1, PERF_COUNT_HW_CPU_CYCLES,
        PERF_FLAG_FD_CLOEXEC, PERF_TYPE_HARDWARE,
    },
    perf_event_open,
};

use crate::meta::ProgMeta;

use super::AttachLink;

fn init_perf_monitor(freq: u64) -> Result<Vec<i32>> {
    let nprocs =
        libbpf_rs::num_possible_cpus().with_context(|| anyhow!("Failed to get processor count"))?;

    let mut attrs = perf_event_attr {
        size: std::mem::size_of::<perf_event_attr>() as u32,
        type_: PERF_TYPE_HARDWARE,
        config: PERF_COUNT_HW_CPU_CYCLES as u64,
        ..Default::default()
    };

    attrs.set_freq(1);
    // This fiels stands for
    //  union {
    //      __u64		sample_period;
    //      __u64		sample_freq;
    // };
    attrs.__bindgen_anon_1 = perf_event_attr__bindgen_ty_1 { sample_freq: freq };

    let mut pefds = vec![];
    for cpu in 0..nprocs {
        // SAFETY: attrs is valid during the call
        let pefd =
            unsafe { perf_event_open(&mut attrs, -1, cpu as i32, -1, PERF_FLAG_FD_CLOEXEC as u64) };
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

    let pefds = init_perf_monitor(1).with_context(|| anyhow!("Failed to init perf monitor"))?;
    debug!("Loaded pefds: {:?}", pefds);
    let mut links = vec![];
    for pefd in pefds.iter() {
        links.push(AttachLink::PerfEventAttachWithFd(
            program.attach_perf_event(*pefd).unwrap(),
            *pefd,
        ))
    }
    Ok(links)
}
