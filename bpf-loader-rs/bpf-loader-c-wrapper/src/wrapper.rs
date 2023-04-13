//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use bpf_loader_lib::skeleton::{handle::PollingHandle, preload::PreLoadBpfSkeleton, BpfSkeleton};

#[repr(C)]
/// A wrapper around skeletons
pub enum SkeletonWrapper {
    /// The preloaded
    PreLoad(PreLoadBpfSkeleton),
    /// The loaded
    Loaded(BpfSkeleton),
    /// None, used for conversions from preload to load
    None,
}
#[repr(C)]
/// A wrapper aroung PollingHandle
pub struct HandleWrapper {
    pub(crate) handle: PollingHandle,
}
