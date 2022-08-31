#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate link_cplusplus;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
