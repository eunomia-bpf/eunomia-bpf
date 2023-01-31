//! # A rust binding for eunomia-bpf
//!
//! develop an approach to compile, transmit, and run most
//! libbpf CO-RE objects with some user space config meta
//! data to help us load and operator the eBPF byte code.
/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::{anyhow, Result};
use std::{sync::Arc, sync::Weak};
extern crate link_cplusplus;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl<'a> Drop for BPFProgram<'a> {
    fn drop(&mut self) {
        if self.ctx.is_null() {
            return;
        }
        unsafe { free_ebpf_program(self.ctx) };
        self.ctx = std::ptr::null_mut();
    }
}

pub struct BPFEvent<'b> {
    pub messgae: &'b str,
}

/// impl this trait to handle the bpf events
pub trait HandleBPFEvent {
    fn on_event(&self, event: &BPFEvent);
}

/// The eunomia ebpf rust bindings.
pub struct BPFProgram<'a> {
    ctx: *mut eunomia_bpf,
    handlers: Vec<Arc<Weak<dyn HandleBPFEvent + 'a>>>,
}

unsafe impl Send for BPFProgram<'_> {}
unsafe impl Sync for BPFProgram<'_> {}

unsafe extern "C" fn raw_handler_callback(
    ctx: *mut ::std::os::raw::c_void,
    event: *const ::std::os::raw::c_char,
) {
    let bpf_program = &*(ctx as *const BPFProgram);
    if event.is_null() {
        return;
    }
    let event = BPFEvent {
        messgae: std::ffi::CStr::from_ptr(event).to_str().unwrap(),
    };
    for handler in &bpf_program.handlers {
        if let Some(handler) = handler.upgrade() {
            handler.on_event(&event);
        }
    }
}

impl<'a> BPFProgram<'a> {
    /// create a new eunomia bpf program from a json file
    pub fn create_ebpf_program(json_data: String) -> Result<BPFProgram<'a>> {
        if json_data.is_empty() {
            return Err(anyhow!("json data is empty"));
        }
        let ctx =
            unsafe { create_ebpf_program_from_json(json_data.as_bytes().as_ptr() as *const i8) };
        if ctx.is_null() {
            return Err(anyhow!("Failed to create ebpf program"));
        } else {
            Ok(BPFProgram {
                ctx,
                handlers: vec![],
            })
        }
    }
    /// start running the ebpf program
    ///
    /// load and attach the ebpf program to the kernel to run the ebpf program
    /// if the ebpf program has maps to export to user space, you need to call
    /// the wait and export.
    pub fn run(&self) -> Result<()> {
        let ret = unsafe { run_ebpf_program(self.ctx) };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow!("Failed to run ebpf program"))
        }
    }
    pub fn register_handler(&mut self, cb: Weak<impl HandleBPFEvent + 'a>) -> usize {
        self.handlers.push(Arc::new(cb));
        let id = self.handlers.len();
        id - 1
    }

    /// wait for the program to exit and receive data from export maps
    ///
    /// if the program has a ring buffer or perf event to export data
    /// to user space, the program will help load the map info and poll the
    /// events automatically.
    pub fn wait_and_poll(&self) -> Result<()> {
        let ret = if self.handlers.len() == 0 {
            unsafe { wait_and_poll_ebpf_program(self.ctx) }
        } else {
            unsafe {
                wait_and_poll_ebpf_program_to_handler(
                    self.ctx,
                    export_format_type_EXPORT_JSON,
                    Some(raw_handler_callback),
                    self as *const BPFProgram as *mut ::std::os::raw::c_void,
                )
            }
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow!("Failed to wait and export ebpf program"))
        }
    }
    /// stop, detach, and clean up memory
    ///
    /// This is thread safe with wait_and_poll.
    /// it will notify the wait_and_poll to exit and
    /// wait until it exits.
    pub fn stop(&self) {
        if self.ctx.is_null() {
            return;
        }
        unsafe { stop_ebpf_program(self.ctx) };
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, fs};

    use super::*;

    #[test]
    fn test_link_and_raw_api() {
        unsafe {
            let input = "{}";
            print!("input: {}", input.len());
            let ctx: *mut eunomia_bpf = create_ebpf_program_from_json(input.as_ptr() as *const i8);
            assert!(ctx.is_null());
            let res = run_ebpf_program(ctx);
            assert!(res != 0);
            let res = wait_and_poll_ebpf_program(ctx);
            assert!(res != 0);
            stop_and_clean_ebpf_program(ctx);
            stop_and_clean_ebpf_program(ctx);
        }
    }

    #[test]
    fn test_handler() {
        struct TestHandler {}
        impl HandleBPFEvent for TestHandler {
            fn on_event(&self, event: &BPFEvent) {
                assert_eq!(event.messgae, "test");
            }
        }
        let handler = Arc::new(TestHandler {});
        let mut ebpf_program = BPFProgram {
            ctx: std::ptr::null_mut(),
            handlers: vec![],
        };
        ebpf_program.register_handler(Arc::downgrade(&handler));
        let test_str = "test";
        let cstr = CString::new(test_str).unwrap();
        // send a signal to the program
        unsafe {
            raw_handler_callback(
                &ebpf_program as *const BPFProgram as *mut ::std::os::raw::c_void,
                cstr.as_ptr(),
            )
        };
    }

    #[test]
    fn test_run_program() {
        let json_data = fs::read_to_string("tests/package.json").unwrap();
        let ebpf_program = Arc::new(BPFProgram::create_ebpf_program(json_data).unwrap());
        let handler = ebpf_program.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            handler.stop();
        });
        ebpf_program.run().unwrap();
        ebpf_program.wait_and_poll().unwrap();
    }
}
