//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::{fs, path};

use clap::Parser;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::debug;
use tempfile::TempDir;

use crate::compile_bpf;
use crate::config::{
    get_bpf_sys_include_args, get_eunomia_include_args, init_eunomia_workspace, CompileArgs,
    Options,
};
use crate::helper::get_target_arch;
use crate::tests::get_test_assets_dir;

use super::{
    claim_output_artifact, ensure_output_artifact_can_be_written, pack_object_in_config,
    write_output_artifact_owner_marker,
};

fn setup_tests(test_name: &str) -> (String, String, PathBuf) {
    let assets_dir = get_test_assets_dir();
    let test_bpf = std::fs::read_to_string(assets_dir.join("client.bpf.c")).unwrap();
    let test_event = std::fs::read_to_string(assets_dir.join("event.h")).unwrap();
    let tmp_dir = path::Path::new(TEMP_EUNOMIA_DIR);
    let tmp_dir = tmp_dir.join(test_name);
    fs::create_dir_all(&tmp_dir).unwrap();
    std::fs::copy(
        assets_dir.join("other_header.h"),
        tmp_dir.join("other_header.h"),
    )
    .unwrap();
    (test_bpf, test_event, tmp_dir)
}

#[test]
fn test_get_attr() {
    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    let args = Options {
        tmpdir: tmp_workspace,
        compile_opts: CompileArgs::try_parse_from(["ecc", "_"]).unwrap(),
        object_name: "".to_string(),
    };

    let sys_include = get_bpf_sys_include_args(&args.compile_opts).unwrap();
    println!("{:?}", sys_include);
    let target_arch = get_target_arch();
    println!("{}", target_arch);
    let eunomia_include = get_eunomia_include_args(&args).unwrap();
    println!("{:?}", eunomia_include);
}

#[test]
fn test_generate_custom_btf() {
    let (test_bpf, test_event, tmp_dir) = setup_tests("_test_generate_custom_btf");
    println!("Working directory: {:?}", tmp_dir);
    let source_path = tmp_dir.join("client.bpf.c");
    println!("source_path: {}", source_path.to_str().unwrap());
    fs::write(&source_path, test_bpf).unwrap();
    let event_path = tmp_dir.join("event.h");
    fs::write(&event_path, test_event).unwrap();
    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    // create a fake btfhub archive
    let btfhub_archive_path = "/tmp/eunomia/test_btfhub_archive".to_string();
    fs::create_dir_all(&btfhub_archive_path).unwrap();
    let tar_path = btfhub_archive_path.clone() + "/4.10.0-1004-gcp.btf.tar.xz";
    Command::new("wget")
            .args(["https://github.com/aquasecurity/btfhub-archive/raw/main/ubuntu/16.04/x86_64/4.10.0-1004-gcp.btf.tar.xz", "-O", &tar_path])
            .output()
            .expect("failed to get btfhub file");
    let cp_args = CompileArgs::try_parse_from([
        "ecc",
        source_path.to_str().unwrap(),
        event_path.to_str().unwrap(),
        "--output-path",
        tmp_dir.to_str().unwrap(),
        "--btfgen",
        "--btfhub-archive",
        &btfhub_archive_path,
    ])
    .unwrap();
    debug!("{:#?}", cp_args);
    let mut args = Options {
        tmpdir: tmp_workspace,
        compile_opts: cp_args,
        object_name: "test".to_string(),
    };
    compile_bpf(&args).unwrap();
    args.compile_opts.yaml = true;
    compile_bpf(&args).unwrap();
    fs::remove_dir_all(tmp_dir).unwrap();
}

#[test]
fn test_compile_bpf() {
    let (test_bpf, test_event, tmp_dir) = setup_tests("test_compile_bpf");

    let source_path = tmp_dir.join("client.bpf.c");
    println!("source_path: {}", source_path.to_str().unwrap());
    fs::write(&source_path, test_bpf).unwrap();
    let event_path = tmp_dir.join("event.h");
    fs::write(&event_path, test_event).unwrap();
    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    let cp_args = CompileArgs::try_parse_from([
        "ecc",
        source_path.to_str().unwrap(),
        event_path.to_str().unwrap(),
        "--output-path",
        tmp_dir.to_str().unwrap(),
    ])
    .unwrap();
    let mut args = Options {
        tmpdir: tmp_workspace,
        compile_opts: cp_args,
        object_name: "test".to_string(),
    };
    compile_bpf(&args).unwrap();
    args.compile_opts.yaml = true;
    compile_bpf(&args).unwrap();
    fs::remove_dir_all(tmp_dir).unwrap();
}

#[test]
fn test_export_multi_and_pack() {
    let (test_bpf, test_event, tmp_dir) = setup_tests("test_export_multi_and_pack");

    let source_path = tmp_dir.join("export_multi_struct.bpf.c");
    fs::write(&source_path, test_bpf).unwrap();
    let event_path = tmp_dir.join("event.h");
    fs::write(&event_path, test_event).unwrap();
    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    let cp_args = CompileArgs::try_parse_from([
        "ecc",
        source_path.to_str().unwrap(),
        event_path.to_str().unwrap(),
        "--output-path",
        tmp_dir.to_str().unwrap(),
    ])
    .unwrap();
    let args = Options {
        tmpdir: tmp_workspace,
        compile_opts: cp_args,
        object_name: "export_multi_struct_test".to_string(),
    };
    compile_bpf(&args).unwrap();
    pack_object_in_config(&args).unwrap();
    let _ = fs::remove_dir_all(tmp_dir);
}

#[test]
fn test_compress_and_pack() {
    let bpf_object = "hello world hello world hello world".as_bytes();
    let _ = base64::encode(&bpf_object);
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(&bpf_object).unwrap();
    let compressed_bytes = e.finish().unwrap();
    let _ = base64::encode(&compressed_bytes);
}

fn write_test_meta_config(args: &Options) {
    let meta = if args.compile_opts.yaml {
        "meta:\n  ok: true\n".to_string()
    } else {
        "{\"meta\":{\"ok\":true}}".to_string()
    };
    fs::write(args.get_output_config_path(), meta).unwrap();
}

fn create_pack_test_args_from_source_path(
    output_dir: &TempDir,
    source_path: &path::Path,
    yaml: bool,
) -> Options {
    let mut compile_opts = CompileArgs::try_parse_from([
        "ecc",
        source_path.to_str().unwrap(),
        "--output-path",
        output_dir.path().to_str().unwrap(),
    ])
    .unwrap();
    compile_opts.yaml = yaml;

    Options {
        tmpdir: TempDir::new().unwrap(),
        compile_opts,
        object_name: source_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .split('.')
            .next()
            .unwrap()
            .to_string(),
    }
}

fn create_pack_test_args(output_dir: &TempDir, source_name: &str, yaml: bool) -> Options {
    let source_path = output_dir.path().join(source_name);
    fs::write(&source_path, "int x;").unwrap();
    create_pack_test_args_from_source_path(output_dir, &source_path, yaml)
}

#[test]
fn test_pack_object_in_config_switches_package_formats_cleanly() {
    let output_dir = TempDir::new().unwrap();
    let mut args = create_pack_test_args(&output_dir, "client.bpf.c", false);

    fs::write(args.get_output_object_path(), b"hello world").unwrap();

    write_test_meta_config(&args);
    pack_object_in_config(&args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(!output_dir.path().join("package.yaml").exists());
    assert!(args.get_output_package_marker_path().exists());

    args.compile_opts.yaml = true;
    write_test_meta_config(&args);
    pack_object_in_config(&args).unwrap();

    assert!(args.get_output_package_config_path().exists());
    assert!(!output_dir.path().join("package.json").exists());
    assert!(!args.get_output_sibling_package_marker_path().exists());

    args.compile_opts.yaml = false;
    write_test_meta_config(&args);
    pack_object_in_config(&args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(!output_dir.path().join("package.yaml").exists());
    assert!(!args.get_output_sibling_package_marker_path().exists());
}

#[test]
fn test_pack_object_in_config_keeps_other_program_sibling_package() {
    let output_dir = TempDir::new().unwrap();

    let json_args = create_pack_test_args(&output_dir, "first.bpf.c", false);
    fs::write(json_args.get_output_object_path(), b"first").unwrap();
    write_test_meta_config(&json_args);
    pack_object_in_config(&json_args).unwrap();

    let yaml_args = create_pack_test_args(&output_dir, "second.bpf.c", true);
    fs::write(yaml_args.get_output_object_path(), b"second").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());
    assert!(json_args.get_output_package_marker_path().exists());
    assert!(yaml_args.get_output_package_marker_path().exists());
}

#[test]
fn test_pack_object_in_config_rejects_other_program_same_format_package() {
    let output_dir = TempDir::new().unwrap();

    let json_args = create_pack_test_args(&output_dir, "first.bpf.c", false);
    fs::write(json_args.get_output_object_path(), b"first").unwrap();
    write_test_meta_config(&json_args);
    pack_object_in_config(&json_args).unwrap();

    let other_json_args = create_pack_test_args(&output_dir, "second.bpf.c", false);
    fs::write(other_json_args.get_output_object_path(), b"second").unwrap();
    write_test_meta_config(&other_json_args);
    let err = pack_object_in_config(&other_json_args).err().unwrap();

    assert!(err.to_string().contains("belongs to a different source"));
}

#[test]
fn test_output_artifact_guard_rejects_other_source_same_basename_btfgen_stage() {
    let output_dir = TempDir::new().unwrap();
    let source_dir_a = TempDir::new().unwrap();
    let source_dir_b = TempDir::new().unwrap();
    let source_path_a = source_dir_a.path().join("shared.bpf.c");
    let source_path_b = source_dir_b.path().join("shared.bpf.c");
    fs::write(&source_path_a, "int x;").unwrap();
    fs::write(&source_path_b, "int x;").unwrap();

    let args_a = create_pack_test_args_from_source_path(&output_dir, &source_path_a, false);
    let args_b = create_pack_test_args_from_source_path(&output_dir, &source_path_b, false);

    fs::create_dir_all(args_a.get_output_btf_archive_directory()).unwrap();
    write_output_artifact_owner_marker(&args_a, args_a.get_output_btf_archive_directory()).unwrap();

    let err =
        ensure_output_artifact_can_be_written(&args_b, args_b.get_output_btf_archive_directory())
            .err()
            .unwrap();

    assert!(err.to_string().contains("belongs to a different source"));
}

#[test]
fn test_claimed_partial_artifact_is_not_unowned_on_retry() {
    let output_dir = TempDir::new().unwrap();

    let args = create_pack_test_args(&output_dir, "client.bpf.c", false);
    let artifact_path = args.get_standalone_executable_path();

    claim_output_artifact(&args, &artifact_path).unwrap();
    fs::write(&artifact_path, b"partial").unwrap();

    ensure_output_artifact_can_be_written(&args, &artifact_path).unwrap();
    assert!(args
        .get_output_artifact_marker_path(&artifact_path)
        .exists());
}

#[test]
fn test_claim_output_artifact_reserves_fresh_path_for_first_source() {
    let output_dir = TempDir::new().unwrap();

    let first_args = create_pack_test_args(&output_dir, "first.bpf.c", false);
    let second_args = create_pack_test_args(&output_dir, "second.bpf.c", false);
    let artifact_path = first_args.get_output_package_config_path();

    claim_output_artifact(&first_args, &artifact_path).unwrap();
    let err = claim_output_artifact(&second_args, &artifact_path)
        .err()
        .unwrap();

    assert!(err.to_string().contains("belongs to a different source"));
}
