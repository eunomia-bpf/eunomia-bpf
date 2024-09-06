//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::os::fd::{self, FromRawFd};

use libbpf_rs::{
    libbpf_sys::{bpf_tc_hook, bpf_tc_hook_destroy, bpf_xdp_attach_opts, bpf_xdp_detach},
    Link,
};
use log::{debug, error};

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
    PerfEventAttachWithFd(Link, i32),
}

impl Drop for AttachLink {
    fn drop(&mut self) {
        match self {
            AttachLink::BpfLink(_link) => {}
            AttachLink::TCAttach(hook) => {
                let err = unsafe { bpf_tc_hook_destroy(&mut **hook) };
                if err != 0 {
                    error!("Failed to destroy tc hook: \n{:?}", err);
                }
            }
            AttachLink::XDPAttach(ifindex, flags, opts) => {
                let err = unsafe { bpf_xdp_detach(*ifindex, *flags, &**opts) };
                if err != 0 {
                    error!("Failed to detach xdp: \n{:?}", err);
                }
            }
            AttachLink::PerfEventAttachWithFd(_link, fd) => {
                debug!("Closing pefd {}", fd);
                // SAFETY: fds are created by us, they are gurateended to be correct
                let _ = unsafe { fd::OwnedFd::from_raw_fd(*fd as _) };
            }
        }
    }
}
