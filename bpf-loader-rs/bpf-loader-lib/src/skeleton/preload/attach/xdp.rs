//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::{
    libbpf_sys::{bpf_xdp_attach, bpf_xdp_attach_opts},
    Program,
};

use crate::meta::{ProgMeta, XDPProgExtraMeta};

use super::AttachLink;
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
