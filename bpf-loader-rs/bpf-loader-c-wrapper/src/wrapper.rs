use bpf_loader_lib::skeleton::{handle::PollingHandle, preload::PreLoadBpfSkeleton, BpfSkeleton};

#[repr(C)]
/// A wrapper around skeletons
pub enum SkeletonWrapper {
    PreLoad(PreLoadBpfSkeleton),
    Loaded(BpfSkeleton),
    None,
}
#[repr(C)]
/// A wrapper aroung PollingHandle
pub struct HandleWrapper {
    pub handle: PollingHandle,
}
