//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use libbpf_rs::{
    libbpf_sys::{bpf_tc_hook, bpf_tc_hook_destroy, bpf_xdp_attach_opts, bpf_xdp_detach},
    Link,
};
use log::error;

pub(crate) mod perf;
pub(crate) mod tc;
pub(crate) mod xdp;

pub(crate) use perf::attach_perf_event;
pub(crate) use tc::attach_tc;
pub(crate) use xdp::attach_xdp;

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
