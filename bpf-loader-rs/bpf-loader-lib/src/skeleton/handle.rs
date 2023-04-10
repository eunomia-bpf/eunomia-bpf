use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

const PAUSE_BIT: u8 = 1 << 0;
const TERMINATING_BIT: u8 = 1 << 1;

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct PollingHandle {
    state: Arc<AtomicU8>,
}
impl PollingHandle {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(0)),
        }
    }
    pub(crate) fn reset(&self) {
        self.state.store(0, Ordering::Release);
    }
    #[inline]
    pub(crate) fn should_pause(&self) -> bool {
        let t = self.state.load(Ordering::SeqCst);
        t & PAUSE_BIT != 0
    }
    #[inline]
    pub(crate) fn should_terminate(&self) -> bool {
        self.state.load(Ordering::SeqCst) & TERMINATING_BIT != 0
    }
    /// Set the pause state of the poller
    pub fn set_pause(&self, pause: bool) {
        if pause {
            self.state.fetch_or(PAUSE_BIT, Ordering::Relaxed);
        } else {
            self.state.fetch_and(!PAUSE_BIT, Ordering::Relaxed);
        }
    }
    /// Terminate the poller. It will allow `wait_and_poll_to_handler` to return
    pub fn terminate(&self) {
        self.state.fetch_or(TERMINATING_BIT, Ordering::Relaxed);
    }
}
