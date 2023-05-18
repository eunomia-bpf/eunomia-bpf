//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{fs, path::PathBuf};

use clap::Parser;
use tempfile::TempDir;

use crate::config::{init_eunomia_workspace, EunomiaWorkspace};

use super::{get_base_dir_include_args, CompileArgs, Options};

fn init_options(copt: CompileArgs) {
    let mut opts = Options::init(copt, TempDir::new().unwrap()).unwrap();
    opts.compile_opts.parameters.generate_package_json = false;
}

#[test]
fn test_parse_args() {
    init_options(CompileArgs::parse_from(&["ecc", "../test/client.bpf.c"]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "-o",
        "test.o",
    ]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "test.h",
        "-v",
    ]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "test.h",
        "-y",
    ]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "-c",
        "clang",
    ]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "-l",
        "llvm-strip",
    ]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "--header-only",
    ]));
    init_options(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "-w",
        "/tmp/test",
    ]));
}

#[test]
fn test_get_base_dir_include_fail() {
    get_base_dir_include_args(&PathBuf::from("/xxx/test.c")).unwrap_err();
}

#[test]
fn test_init_eunomia_workspace() {
    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    // check if workspace and file successfully created
    let bpftool_path = tmp_workspace.path().join("bin/bpftool");
    assert!(bpftool_path.exists());
    let _ = fs::create_dir_all("/tmp/test_workspace");
    // test specifiy workspace
    EunomiaWorkspace::init(CompileArgs::parse_from(&[
        "ecc",
        "../test/client.bpf.c",
        "-w",
        "/tmp/test_workspace",
    ]))
    .unwrap();

    // test default workspace
    EunomiaWorkspace::init(CompileArgs::parse_from(&["ecc", "../test/client.bpf.c"])).unwrap();
}
