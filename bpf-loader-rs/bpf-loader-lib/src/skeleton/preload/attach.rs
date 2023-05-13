//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{
    libbpf_sys::{
        bpf_tc_attach, bpf_tc_hook, bpf_tc_hook_create, bpf_tc_hook_destroy, bpf_tc_opts,
        bpf_xdp_attach, bpf_xdp_attach_opts, bpf_xdp_detach,
    },
    Link, Program,
};
use log::error;

use crate::meta::{ProgMeta, TCProgExtraMeta, XDPProgExtraMeta};

pub(crate) enum AttachLink {
    BpfLink(Link),
    TCAttach(Box<bpf_tc_hook>),
    XDPAttach(i32, u32, Box<bpf_xdp_attach_opts>),
}

impl Drop for AttachLink {
    fn drop(&mut self) {
        match self {
            AttachLink::BpfLink(_) => {}
            AttachLink::TCAttach(hook) => {
                let err = unsafe { bpf_tc_hook_destroy(&mut **hook) };
                if err != 0 {
                    error!("Failed to destroy tc hook: {}", err);
                }
            }
            AttachLink::XDPAttach(ifindex, flags, opts) => {
                let err = unsafe { bpf_xdp_detach(*ifindex, *flags, &**opts) };
                if err != 0 {
                    error!("Failed to detach xdp: {}", err);
                }
            }
        }
    }
}

pub(crate) fn attach_xdp(program: &Program, meta: &ProgMeta) -> Result<AttachLink> {
    let xdp_extra_meta = serde_json::from_value::<XDPProgExtraMeta>(meta.others.clone())
        .with_context(|| anyhow!("Failed to deserialize xdp extra meta"))?;

    let ifindex = xdp_extra_meta.ifindex;
    let flags = xdp_extra_meta.flags;
    let prog_fd = program.fd();

    // SAFETY: it's a C-repr struct, and only contains scalars. So it's safe to fill it with zero
    let mut xdp_attach_opts = Box::new(unsafe { std::mem::zeroed::<bpf_xdp_attach_opts>() });
    xdp_attach_opts.sz = std::mem::size_of::<bpf_xdp_attach_opts>() as _;
    xdp_attach_opts.old_prog_fd = xdp_extra_meta.xdpopts.old_prog_fd;

    // SAFETY: xdp_attach_opts is valid during the call
    let err = unsafe { bpf_xdp_attach(ifindex, prog_fd, flags, &*xdp_attach_opts) };
    if err < 0 {
        bail!("Failed to attach xdp: {}", err);
    }

    Ok(AttachLink::XDPAttach(ifindex, flags, xdp_attach_opts))
}

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
