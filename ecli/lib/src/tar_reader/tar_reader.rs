//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use eunomia_rs::TempDir;
use std::fs;
use tar::Archive;

pub fn unpack_tar(tar_data: &[u8]) -> (Vec<u8>, Option<String>) {
    let mut archive = Archive::new(tar_data);
    let tmpdir = TempDir::new().unwrap();
    let tmpdir_path = tmpdir.path();

    archive.unpack(tmpdir_path).unwrap();

    let json_object_buffer = fs::read(tmpdir_path.join("package.json")).unwrap();
    let btf_archive_path = tmpdir_path
        .join("btfhub-archive")
        .to_string_lossy()
        .to_string();
    println!("{btf_archive_path}");

    (json_object_buffer, Some(btf_archive_path))
}
