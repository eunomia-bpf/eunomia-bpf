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

fn create_source_file() -> (TempDir, PathBuf) {
    let tmp_source_dir = TempDir::new().unwrap();
    let source_path = tmp_source_dir.path().join("test.bpf.c");
    fs::write(&source_path, "int x;").unwrap();
    (tmp_source_dir, source_path)
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

#[test]
fn test_output_package_path_tracks_selected_format() {
    let (_tmp_source_dir, source_path) = create_source_file();

    let args = create_initialized_options(source_path.to_str().unwrap());
    assert_eq!(
        args.get_output_package_config_path(),
        source_path.parent().unwrap().join("package.json")
    );

    let mut yaml_args = create_initialized_options(source_path.to_str().unwrap());
    yaml_args.compile_opts.yaml = true;
    assert_eq!(
        yaml_args.get_output_package_config_path(),
        source_path.parent().unwrap().join("package.yaml")
    );
    assert_eq!(
        yaml_args.get_output_sibling_package_config_path(),
        source_path.parent().unwrap().join("package.json")
    );
}

#[test]
fn test_output_btf_archive_directory_is_object_scoped() {
    let (_tmp_source_dir, source_path) = create_source_file();

    let args = create_initialized_options(source_path.to_str().unwrap());
    assert_eq!(
        args.get_output_btf_archive_directory(),
        source_path.parent().unwrap().join("test.custom-archive")
    );
}

#[test]
fn test_source_file_temp_path_uses_workspace_and_object_name() {
    let (_tmp_source_dir, source_path) = create_source_file();

    let args = create_initialized_options(source_path.to_str().unwrap());
    assert_eq!(
        args.get_source_file_temp_path(),
        args.get_workspace_directory().join("test.temp.c")
    );
}

#[test]
fn test_reject_yaml_modes_that_require_json_package_output() {
    let (_tmp_source_dir, source_path) = create_source_file();

    for cli_args in [
        vec![
            "ecc",
            source_path.to_str().unwrap(),
            "--yaml",
            "--wasm-header",
        ],
        vec![
            "ecc",
            source_path.to_str().unwrap(),
            "--yaml",
            "--standalone",
        ],
        vec!["ecc", source_path.to_str().unwrap(), "--yaml", "--btfgen"],
    ] {
        let compile_opts = CompileArgs::parse_from(cli_args);
        let err = Options::init(compile_opts, TempDir::new().unwrap())
            .err()
            .unwrap();
        assert!(err.to_string().contains("requires JSON package output"));
    }
}

#[test]
fn test_reject_modes_that_require_generated_package_output() {
    let (_tmp_source_dir, source_path) = create_source_file();

    for cli_args in [
        vec![
            "ecc",
            source_path.to_str().unwrap(),
            "--no-generate-package-json",
            "--wasm-header",
        ],
        vec![
            "ecc",
            source_path.to_str().unwrap(),
            "--no-generate-package-json",
            "--btfgen",
        ],
    ] {
        let compile_opts = CompileArgs::parse_from(cli_args);
        let err = Options::init(compile_opts, TempDir::new().unwrap())
            .err()
            .unwrap();
        assert!(err
            .to_string()
            .contains("requires a generated package artifact"));
    }

    let mut compile_opts = CompileArgs::parse_from(["ecc", source_path.to_str().unwrap()]);
    compile_opts.parameters.no_generate_package_json = true;
    compile_opts.parameters.standalone = true;
    let err = Options::init(compile_opts, TempDir::new().unwrap())
        .err()
        .unwrap();
    assert!(err
        .to_string()
        .contains("requires a generated package artifact"));
}
