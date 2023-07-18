//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{
    libbpf_sys::{
        bpf_tc_attach, bpf_tc_hook, bpf_tc_hook_create, bpf_tc_hook_destroy, bpf_tc_opts,
    },
    Program,
};

use crate::meta::{ProgMeta, TCProgExtraMeta};

use super::AttachLink;

pub(crate) fn attach_tc(program: &Program, meta: &ProgMeta) -> Result<AttachLink> {
    let tc_extra_meta = serde_json::from_value::<TCProgExtraMeta>(meta.others.clone())
        .with_context(|| anyhow!("Failed to deserialize tc extra meta"))?;
    // SAFETY: it's a C-repr struct, and only contains scalars. So it's safe to fill it with zero
    let mut tc_hook = Box::new(unsafe { std::mem::zeroed::<bpf_tc_hook>() });
    tc_hook.sz = std::mem::size_of::<bpf_tc_hook>() as _;
    tc_hook.attach_point = tc_extra_meta.tchook.attach_point.to_value();
    tc_hook.ifindex = tc_extra_meta.tchook.ifindex;
    // SAFETY: tc_hook is valid during the call
    let err = unsafe { bpf_tc_hook_create(&mut *tc_hook) };
    /* The hook (i.e. qdisc) may already exists because:
     *   1. it is created by other processes or users
     *   2. or since we are attaching to the TC ingress ONLY,
     *      bpf_tc_hook_destroy does NOT really remove the qdisc,
     *      there may be an egress filter on the qdisc
     */
    if err != 0 && err != -17
    /*EEXIST = 17*/
    {
        bail!("Failed to create tc hook: {}", err);
    }
    // SAFETY: it's a C-repr struct, and only contains scalars. So it's safe to fill it with zero
    let mut tc_opts = Box::new(unsafe { std::mem::zeroed::<bpf_tc_opts>() });
    tc_opts.sz = std::mem::size_of::<bpf_tc_opts>() as _;
    tc_opts.handle = tc_extra_meta.tcopts.handle;
    tc_opts.priority = tc_extra_meta.tcopts.priority;
    tc_opts.prog_fd = program.fd();
    // SAFETY: pointers are valid
    let err = unsafe { bpf_tc_attach(&*tc_hook, &mut *tc_opts) };
    if err != 0 && err != -17 {
        // SAFETY: pointer is valid
        unsafe { bpf_tc_hook_destroy(&mut *tc_hook) };
        bail!("Failed to attach tc: {}", err);
    }
    Ok(AttachLink::TCAttach(tc_hook))
}
