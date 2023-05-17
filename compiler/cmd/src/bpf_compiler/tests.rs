const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::{fs, path};

use flate2::write::ZlibEncoder;
use flate2::Compression;
use tempfile::TempDir;

use crate::compile_bpf;
use crate::config::{
    get_bpf_sys_include, get_eunomia_include, get_target_arch, init_eunomia_workspace, CompileArgs,
    CompileExtraArgs, Options,
};
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
        compile_opts: CompileArgs {
            ..Default::default()
        },
    };

    let sys_include = get_bpf_sys_include(&args.compile_opts).unwrap();
    println!("{}", sys_include);
    let target_arch = get_target_arch();
    println!("{}", target_arch);
    let eunomia_include = get_eunomia_include(&args).unwrap();
    println!("{}", eunomia_include);
}

#[test]
fn test_generate_custom_btf() {
    let (test_bpf, test_event, tmp_dir) = setup_tests("_test_generate_custom_btf");

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

    let mut args = Options {
        tmpdir: tmp_workspace,
        compile_opts: CompileArgs {
            btfgen: true,
            btfhub_archive: btfhub_archive_path,
            source_path: source_path.to_str().unwrap().to_string(),
            output_path: "/tmp/eunomia/test".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
            parameters: CompileExtraArgs {
                clang_bin: "clang".to_string(),
                llvm_strip_bin: "llvm-strip".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };
    compile_bpf(&args).unwrap();
    args.compile_opts.yaml = true;
    compile_bpf(&args).unwrap();
    let _ = fs::remove_dir_all(tmp_dir);
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

    let mut args = Options {
        tmpdir: tmp_workspace,
        compile_opts: CompileArgs {
            source_path: source_path.to_str().unwrap().to_string(),
            output_path: "/tmp/eunomia/test".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
            parameters: CompileExtraArgs {
                clang_bin: "clang".to_string(),
                llvm_strip_bin: "llvm-strip".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };
    compile_bpf(&args).unwrap();
    args.compile_opts.yaml = true;
    compile_bpf(&args).unwrap();
    let _ = fs::remove_dir_all(tmp_dir);
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

    let args = Options {
        tmpdir: tmp_workspace,
        compile_opts: CompileArgs {
            source_path: source_path.to_str().unwrap().to_string(),
            output_path: "/tmp/eunomia/export_multi_struct_test".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
            parameters: CompileExtraArgs {
                clang_bin: "clang".to_string(),
                llvm_strip_bin: "llvm-strip".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
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
