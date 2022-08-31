//! # A rust binding for eunomia-bpf
//!
//! develop an approach to compile, transmit, and run most
//! libbpf CO-RE objects with some user space config meta
//! data to help us load and operator the eBPF byte code.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::error::Error;

extern crate link_cplusplus;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// The eunomia ebpf rust bindings.
pub struct Eunomia_bpf_program {
    ctx: *mut eunomia_bpf,
}

impl Eunomia_bpf_program {
    /// create a new eunomia bpf program from a json file
    pub fn create_ebpf_program(json_data: &str) -> Result<Eunomia_bpf_program, &str> {
        let ctx =
            unsafe { create_ebpf_program_from_json(json_data.as_bytes().as_ptr() as *const i8) };
        if ctx.is_null() {
            return Err("Failed to create ebpf program");
        } else {
            Ok(Eunomia_bpf_program { ctx })
        }
    }
    /// start running the ebpf program
    ///
    /// load and attach the ebpf program to the kernel to run the ebpf program
    /// if the ebpf program has maps to export to user space, you need to call
    /// the wait and export.
    pub fn run(&self) -> Result<(), &str> {
        let ret = unsafe { run_ebpf_program(self.ctx) };
        if ret == 0 {
            Ok(())
        } else {
            Err("Failed to run ebpf program")
        }
    }
    /// wait for the program to exit and receive data from export maps
    ///
    /// if the program has a ring buffer or perf event to export data
    /// to user space, the program will help load the map info and poll the
    /// events automatically.
    pub fn wait_and_export(&self) -> Result<(), &str> {
        let ret = unsafe { wait_and_export_ebpf_program(self.ctx) };
        if ret == 0 {
            Ok(())
        } else {
            Err("Failed to wait and export ebpf program")
        }
    }
    /// stop, detach, and clean up memory
    ///
    /// This is thread safe with wait_and_export.
    /// it will notify the wait_and_export to exit and
    /// wait until it exits.
    pub fn stop(&self) {
        unsafe { stop_and_clean_ebpf_program(self.ctx) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expected_failure]
    fn test_run_ebpf_program() {
        unsafe {
            let input =
                include_str!("../../../bpftools/examples/bindsnoop/package.json").as_bytes();
            let ctx: *mut eunomia_bpf = create_ebpf_program_from_json(input.as_ptr() as *const i8);
            assert!(!ctx.is_null());
            let res = run_ebpf_program(ctx);
            assert!(res == 0);
            let res = wait_and_export_ebpf_program(ctx);
            assert!(res == 0);
            stop_and_clean_ebpf_program(ctx);
        }
    }
}
