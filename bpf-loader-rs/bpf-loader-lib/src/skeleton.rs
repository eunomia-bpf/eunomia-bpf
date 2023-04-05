use crate::state::EbpfProgramState;
#[allow(unused)]
pub struct BpfSkeleton {
    /// The state of eunomia-bpf program
    state: EbpfProgramState,
    /// is the polling ring buffer loop exiting?
    exiting: std::sync::Mutex<bool>,
    
}
