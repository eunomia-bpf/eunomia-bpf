//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{fs, path::PathBuf};

use clap::Parser;
use tempfile::TempDir;

use crate::config::{init_eunomia_workspace, EunomiaWorkspace};

use super::{get_base_dir_include_args, get_bpf_compile_args, CompileArgs, Options};

fn init_options(copt: CompileArgs) {
    let mut opts = Options::init(copt, TempDir::new().unwrap()).unwrap();
    opts.compile_opts.parameters.no_generate_package_json = true;
}

fn create_initialized_options(source_path: &str) -> Options {
    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    let compile_opts = CompileArgs::parse_from(["ecc", source_path]);
    Options::init(compile_opts, tmp_workspace).unwrap()
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
    // test specify workspace
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

#[test]
fn test_get_bpf_compile_args_split_target_and_use_source_dir() {
    let tmp_source_dir = TempDir::new().unwrap();
    let source_dir = tmp_source_dir.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("test.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let args = create_initialized_options(source_path.to_str().unwrap());
    let compile_args = get_bpf_compile_args(&args, &args.compile_opts.source_path).unwrap();
    let source_include = format!("-I{}", source_dir.canonicalize().unwrap().display());

    assert!(compile_args
        .windows(2)
        .any(|window| window == ["-target", "bpf"]));
    assert!(!compile_args.iter().any(|arg| arg == "-target bpf"));
    assert!(compile_args.iter().any(|arg| arg == &source_include));
}
