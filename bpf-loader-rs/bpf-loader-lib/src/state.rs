pub enum EbpfProgramState {
    /// The config is set but the program is not loaded
    Init,
    /// The program is loaded and attached to the kernel
    Running,
    /// The program is stopped
    Stopped,
    /// invalid format or cannot be load
    Invalid,
}
