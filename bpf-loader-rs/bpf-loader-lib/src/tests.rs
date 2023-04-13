//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::path::PathBuf;

use serde::Deserialize;

pub(crate) fn get_assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets")
}

#[derive(Deserialize, Debug)]
pub(crate) struct ExampleTestStruct {
    arr1: [[[i32; 4]; 3]; 2],
    str: String,
    str_arr: [String; 10],
    ft: f32,
    dbl: f64,
    u8v: u8,
    i8v: i8,
    u16v: u16,
    i16v: i16,
    u32v: u32,
    i32v: i32,
    u64v: u64,
    i64v: i64,
    e: String,
}
impl ExampleTestStruct {
    pub(crate) fn test_with_example_data(&self) {
        assert_eq!(self.ft, 1.23);
        assert_eq!(self.dbl, 4.56);
        assert_eq!(self.u8v, 0x12);
        assert_eq!(self.u16v, 0x1234);
        assert_eq!(self.u32v, 0x12345678);
        assert_eq!(self.u64v, 0x123456789abcdef0);
        assert_eq!(self.i8v, -0x12);
        assert_eq!(self.i16v, -0x1234);
        assert_eq!(self.i32v, -0x12345678);
        assert_eq!(self.i64v, -0x123456789abcdef0);
        assert_eq!(self.e, "E_A(0)");
        assert_eq!(self.str, "A-String");
        for i in 0..2 {
            for j in 0..3 {
                for k in 0..4 {
                    assert_eq!(self.arr1[i][j][k] as usize, (i << 16) + (j << 8) + k);
                }
            }
        }
        for i in 0..10 {
            assert_eq!(self.str_arr[i], format!("hello {}", i));
        }
    }
}
