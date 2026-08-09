//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::{fs, path};

use clap::Parser;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::debug;
use serde_json::Value;
use tempfile::TempDir;

use crate::compile_bpf;
use crate::config::{
    get_bpf_sys_include_args, get_eunomia_include_args, init_eunomia_workspace, CompileArgs,
    Options,
};
use crate::helper::get_target_arch;
use crate::tests::get_test_assets_dir;

use super::pack_object_in_config;

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

#[test]
fn test_compile_header_only_respects_export_annotations_and_hides_dummy_symbols() {
    let output_dir = TempDir::new().unwrap();
    let header_path = output_dir.path().join("header_only.h");
    fs::write(
        &header_path,
        r#"
            #ifndef HEADER_ONLY_H
            #define HEADER_ONLY_H

            struct helper {
                int ignored;
            };

            /* struct commented_out {
                int ignored;
            }; */

            #if 0
            struct disabled {
                int ignored;
            };
            #endif

            /// @export
            struct selected_event {
                int pid;
            };

            typedef struct helper_typedef {
                int ignored;
            } helper_typedef_t;

            #endif
        "#,
    )
    .unwrap();

    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    let cp_args = CompileArgs::try_parse_from([
        "ecc",
        header_path.to_str().unwrap(),
        "--header-only",
        "--output-path",
        output_dir.path().to_str().unwrap(),
    ])
    .unwrap();
    let args = Options::init(cp_args, tmp_workspace).unwrap();
    compile_bpf(&args).unwrap();

    let meta_path = output_dir.path().join("header_only.skel.json");
    let meta_json: Value = serde_json::from_str(&fs::read_to_string(meta_path).unwrap()).unwrap();
    let export_types = meta_json["export_types"].as_array().unwrap();
    assert_eq!(export_types.len(), 1);
    assert_eq!(export_types[0]["name"].as_str().unwrap(), "selected_event");

    if let Some(data_sections) = meta_json["bpf_skel"]["data_sections"].as_array() {
        for data_section in data_sections {
            let variables = data_section["variables"].as_array().unwrap();
            assert!(variables.iter().all(|variable| {
                !variable["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("__eunomia_dummy_")
            }));
        }
    }
    if let Some(maps) = meta_json["bpf_skel"]["maps"].as_array() {
        assert!(maps
            .iter()
            .all(|map| map["ident"].as_str().unwrap_or_default() != "bss"));
    }
}

#[test]
fn test_compile_header_only_symlink_preserves_include_root_for_docs() {
    let output_dir = TempDir::new().unwrap();
    let real_dir = output_dir.path().join("real");
    let symlink_dir = output_dir.path().join("link");
    fs::create_dir_all(&real_dir).unwrap();
    fs::create_dir_all(&symlink_dir).unwrap();

    let real_header_path = real_dir.join("header_only.h");
    let symlink_header_path = symlink_dir.join("header_only.h");
    fs::write(
        &real_header_path,
        r#"
            #include "shared.h"

            /// @export
            struct selected_event {
                shared_int_t pid;
            };
        "#,
    )
    .unwrap();
    fs::write(symlink_dir.join("shared.h"), "typedef int shared_int_t;\n").unwrap();
    symlink(&real_header_path, &symlink_header_path).unwrap();

    let tmp_workspace = TempDir::new().unwrap();
    init_eunomia_workspace(&tmp_workspace).unwrap();
    let cp_args = CompileArgs::try_parse_from([
        "ecc",
        symlink_header_path.to_str().unwrap(),
        "--header-only",
        "--output-path",
        output_dir.path().to_str().unwrap(),
    ])
    .unwrap();
    let args = Options::init(cp_args, tmp_workspace).unwrap();

    compile_bpf(&args).unwrap();

    let meta_path = output_dir.path().join("header_only.skel.json");
    let meta_json: Value = serde_json::from_str(&fs::read_to_string(meta_path).unwrap()).unwrap();
    let export_types = meta_json["export_types"].as_array().unwrap();
    assert_eq!(export_types.len(), 1);
    assert_eq!(export_types[0]["name"].as_str().unwrap(), "selected_event");
}
