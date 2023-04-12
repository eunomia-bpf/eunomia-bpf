use bpf_loader_lib::skeleton::{handle::PollingHandle, preload::PreLoadBpfSkeleton, BpfSkeleton};

#[repr(C)]
pub enum SkeletonWrapper {
    PreLoad(PreLoadBpfSkeleton),
    Loaded(BpfSkeleton),
    None,
}
#[repr(C)]
pub struct HandleWrapper {
    pub handle: PollingHandle,
}
