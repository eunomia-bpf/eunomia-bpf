//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;
use std::{fs, path};

use anyhow::anyhow;
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
    build_output_artifact_claim, build_output_artifact_marker, build_output_artifact_owner,
    claim_output_artifact, claim_requested_output_artifacts,
    claim_requested_output_artifacts_for_invocation, create_output_artifact_tempdir,
    create_output_artifact_tempfile, create_output_object_tempfile,
    ensure_output_artifact_can_be_written, get_output_artifact_claim_path,
    get_output_artifact_cleanup_reservation_path,
    normalize_output_artifact_tool_identity_path_with_path_env, pack_object_in_config,
    publish_output_directory_artifact, publish_output_file_artifact,
    publish_output_object_artifact, publish_standalone_artifacts_for_invocation,
    publish_wasm_header_artifact_for_invocation, read_output_artifact_marker,
    release_output_artifact_claim, set_output_artifact_claim_publish_barrier,
    set_output_artifact_claim_release_failure, set_output_artifact_cleanup_reservation_barrier,
    set_output_artifact_marker_publish_barrier, set_output_object_publish_barrier,
    write_output_artifact_owner_marker, OutputArtifactInvocation,
};

fn setup_tests(test_name: &str) -> (String, String, PathBuf) {
    let assets_dir = get_test_assets_dir();
    let test_bpf = std::fs::read_to_string(assets_dir.join("client.bpf.c")).unwrap();
    let test_event = std::fs::read_to_string(assets_dir.join("event.h")).unwrap();
    let tmp_dir = path::Path::new(TEMP_EUNOMIA_DIR);
    let tmp_dir = tmp_dir.join(test_name);
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir).unwrap();
    }
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
fn test_overlapping_same_source_json_yaml_builds_publish_and_pack_shared_object() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("client.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    let output_object_path = output_dir.path().join("client.bpf.o");
    let publish_entered = Arc::new(Barrier::new(3));
    let publish_release = Arc::new(Barrier::new(3));
    let package_claims_held = Arc::new(Barrier::new(3));
    set_output_object_publish_barrier(Some((
        output_object_path.clone(),
        publish_entered.clone(),
        publish_release.clone(),
    )));

    let json_package_claims_held = package_claims_held.clone();
    let json_handle = thread::spawn(move || -> anyhow::Result<()> {
        let claimed_output_artifacts = claim_requested_output_artifacts(&json_args)?;
        let build_result = (|| -> anyhow::Result<()> {
            let mut output_object_file =
                create_output_object_tempfile(json_args.get_output_object_path())?;
            output_object_file.write_all(b"json")?;
            output_object_file.as_file_mut().sync_all()?;

            write_test_meta_config(&json_args);
            publish_output_object_artifact(
                &json_args,
                output_object_file,
                json_args.get_output_object_path(),
            )?;
            pack_object_in_config(&json_args)?;
            json_package_claims_held.wait();
            Ok(())
        })();
        let release_result = claimed_output_artifacts.release();

        match (build_result, release_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(release_err)) => Err(release_err),
            (Err(err), Err(release_err)) => Err(anyhow!(
                "{err}. Failed to release output artifact claims: {release_err}"
            )),
        }
    });
    let yaml_package_claims_held = package_claims_held.clone();
    let yaml_handle = thread::spawn(move || -> anyhow::Result<()> {
        let claimed_output_artifacts = claim_requested_output_artifacts(&yaml_args)?;
        let build_result = (|| -> anyhow::Result<()> {
            let mut output_object_file =
                create_output_object_tempfile(yaml_args.get_output_object_path())?;
            output_object_file.write_all(b"yaml")?;
            output_object_file.as_file_mut().sync_all()?;

            write_test_meta_config(&yaml_args);
            publish_output_object_artifact(
                &yaml_args,
                output_object_file,
                yaml_args.get_output_object_path(),
            )?;
            pack_object_in_config(&yaml_args)?;
            yaml_package_claims_held.wait();
            Ok(())
        })();
        let release_result = claimed_output_artifacts.release();

        match (build_result, release_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(release_err)) => Err(release_err),
            (Err(err), Err(release_err)) => Err(anyhow!(
                "{err}. Failed to release output artifact claims: {release_err}"
            )),
        }
    });

    publish_entered.wait();
    assert!(!output_object_path.exists());
    publish_release.wait();
    package_claims_held.wait();

    let json_result = json_handle.join().unwrap();
    let yaml_result = yaml_handle.join().unwrap();
    set_output_object_publish_barrier(None);

    json_result.unwrap();
    yaml_result.unwrap();
    assert!(output_dir.path().join("client.bpf.o").exists());
    assert!(output_dir.path().join("client.skel.json").exists());
    assert!(output_dir.path().join("client.skel.yaml").exists());
    assert!(output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());
}

#[test]
fn test_publish_output_object_artifact_allows_only_one_same_source_publisher() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    let object_path = output_dir.path().join("shared.bpf.o");
    fs::write(&source_path, "int x;").unwrap();

    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    let json_claim = build_output_artifact_claim(&json_args).unwrap();
    let yaml_claim = build_output_artifact_claim(&yaml_args).unwrap();

    assert!(claim_output_artifact(&json_args, &object_path).unwrap());
    assert!(claim_output_artifact(&yaml_args, &object_path).unwrap());

    let mut json_temp_object = create_output_object_tempfile(&object_path).unwrap();
    json_temp_object.write_all(b"json").unwrap();
    json_temp_object.as_file_mut().sync_all().unwrap();

    let mut yaml_temp_object = create_output_object_tempfile(&object_path).unwrap();
    yaml_temp_object.write_all(b"yaml").unwrap();
    yaml_temp_object.as_file_mut().sync_all().unwrap();

    let publish_entered = Arc::new(Barrier::new(3));
    let publish_release = Arc::new(Barrier::new(3));
    set_output_object_publish_barrier(Some((
        object_path.clone(),
        publish_entered.clone(),
        publish_release.clone(),
    )));

    let json_object_path = object_path.clone();
    let yaml_object_path = object_path.clone();
    let json_handle = thread::spawn(move || {
        publish_output_object_artifact(&json_args, json_temp_object, &json_object_path)
    });
    let yaml_handle = thread::spawn(move || {
        publish_output_object_artifact(&yaml_args, yaml_temp_object, &yaml_object_path)
    });

    publish_entered.wait();
    publish_release.wait();

    let json_result = json_handle.join().unwrap();
    let yaml_result = yaml_handle.join().unwrap();
    set_output_object_publish_barrier(None);

    let json_published = json_result.unwrap();
    let yaml_published = yaml_result.unwrap();
    let output_object = fs::read(&object_path).unwrap();

    assert_ne!(json_published, yaml_published);
    if json_published {
        assert_eq!(output_object, b"json");
    } else {
        assert_eq!(output_object, b"yaml");
    }

    release_output_artifact_claim(&json_claim, &object_path).unwrap();
    release_output_artifact_claim(&yaml_claim, &object_path).unwrap();
}

#[test]
fn test_btfgen_final_artifacts_allow_only_one_same_source_publisher() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let mut first_archive_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    first_archive_args.compile_opts.btfgen = true;
    let mut second_archive_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    second_archive_args.compile_opts.btfgen = true;

    let archive_path = first_archive_args.get_output_btf_archive_directory();
    let tar_path = first_archive_args.get_output_tar_path();
    let first_archive_claim = build_output_artifact_claim(&first_archive_args).unwrap();
    let second_archive_claim = build_output_artifact_claim(&second_archive_args).unwrap();

    assert!(claim_output_artifact(&first_archive_args, &archive_path).unwrap());
    assert!(claim_output_artifact(&second_archive_args, &archive_path).unwrap());

    let first_archive_dir = create_output_artifact_tempdir(&archive_path).unwrap();
    fs::write(first_archive_dir.path().join("first.btf"), b"first").unwrap();
    let second_archive_dir = create_output_artifact_tempdir(&archive_path).unwrap();
    fs::write(second_archive_dir.path().join("second.btf"), b"second").unwrap();

    let archive_start = Arc::new(Barrier::new(3));
    let first_archive_path = archive_path.clone();
    let second_archive_path = archive_path.clone();
    let first_archive_start = archive_start.clone();
    let second_archive_start = archive_start.clone();
    let first_archive_handle = thread::spawn(move || {
        first_archive_start.wait();
        publish_output_directory_artifact(
            &first_archive_args,
            first_archive_dir,
            &first_archive_path,
        )
    });
    let second_archive_handle = thread::spawn(move || {
        second_archive_start.wait();
        publish_output_directory_artifact(
            &second_archive_args,
            second_archive_dir,
            &second_archive_path,
        )
    });

    archive_start.wait();

    let first_archive_result = first_archive_handle.join().unwrap().unwrap();
    let second_archive_result = second_archive_handle.join().unwrap().unwrap();
    assert_ne!(first_archive_result, second_archive_result);
    assert_eq!(
        first_archive_result,
        archive_path.join("first.btf").exists()
    );
    assert_eq!(
        second_archive_result,
        archive_path.join("second.btf").exists()
    );

    release_output_artifact_claim(&first_archive_claim, &archive_path).unwrap();
    release_output_artifact_claim(&second_archive_claim, &archive_path).unwrap();

    let mut first_tar_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    first_tar_args.compile_opts.btfgen = true;
    let mut second_tar_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    second_tar_args.compile_opts.btfgen = true;
    let first_tar_claim = build_output_artifact_claim(&first_tar_args).unwrap();
    let second_tar_claim = build_output_artifact_claim(&second_tar_args).unwrap();

    assert!(claim_output_artifact(&first_tar_args, &tar_path).unwrap());
    assert!(claim_output_artifact(&second_tar_args, &tar_path).unwrap());

    let mut first_tar_file = create_output_artifact_tempfile(&tar_path).unwrap();
    first_tar_file.as_file_mut().write_all(b"first").unwrap();
    first_tar_file.as_file_mut().sync_all().unwrap();
    let mut second_tar_file = create_output_artifact_tempfile(&tar_path).unwrap();
    second_tar_file.as_file_mut().write_all(b"second").unwrap();
    second_tar_file.as_file_mut().sync_all().unwrap();

    let tar_start = Arc::new(Barrier::new(3));
    let first_tar_path = tar_path.clone();
    let second_tar_path = tar_path.clone();
    let first_tar_start = tar_start.clone();
    let second_tar_start = tar_start.clone();
    let first_tar_handle = thread::spawn(move || {
        first_tar_start.wait();
        publish_output_file_artifact(&first_tar_args, first_tar_file, &first_tar_path)
    });
    let second_tar_handle = thread::spawn(move || {
        second_tar_start.wait();
        publish_output_file_artifact(&second_tar_args, second_tar_file, &second_tar_path)
    });

    tar_start.wait();

    let first_tar_result = first_tar_handle.join().unwrap().unwrap();
    let second_tar_result = second_tar_handle.join().unwrap().unwrap();
    assert_ne!(first_tar_result, second_tar_result);
    if first_tar_result {
        assert_eq!(fs::read(&tar_path).unwrap(), b"first");
    } else {
        assert_eq!(fs::read(&tar_path).unwrap(), b"second");
    }

    release_output_artifact_claim(&first_tar_claim, &tar_path).unwrap();
    release_output_artifact_claim(&second_tar_claim, &tar_path).unwrap();
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
    let tmpdir = TempDir::new().unwrap();
    init_eunomia_workspace(&tmpdir).unwrap();
    let mut compile_opts = CompileArgs::try_parse_from([
        "ecc",
        source_path.to_str().unwrap(),
        "--output-path",
        output_dir.path().to_str().unwrap(),
    ])
    .unwrap();
    compile_opts.yaml = yaml;

    Options {
        tmpdir,
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

fn assert_output_artifact_finalized(args: &Options, artifact_path: impl AsRef<path::Path>) {
    let marker =
        read_output_artifact_marker(args.get_output_artifact_marker_path(artifact_path)).unwrap();
    assert!(marker.finalized_at_unix_nanos.is_some());
}

fn write_legacy_output_artifact_marker(args: &Options, artifact_path: impl AsRef<path::Path>) {
    let marker_path = args.get_output_artifact_marker_path(&artifact_path);
    let owner = build_output_artifact_owner(args).unwrap();
    let mut marker_json =
        serde_json::to_value(build_output_artifact_marker(&owner, Some(1))).unwrap();
    marker_json["owner"]
        .as_object_mut()
        .unwrap()
        .remove("source_snapshot");
    marker_json
        .as_object_mut()
        .unwrap()
        .remove("finalized_at_unix_nanos");
    fs::write(marker_path, serde_json::to_vec(&marker_json).unwrap()).unwrap();
}

fn write_legacy_output_artifact_claim(args: &Options, artifact_path: impl AsRef<path::Path>) {
    let claim_path = get_output_artifact_claim_path(args, artifact_path);
    fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
    let mut claim_json = serde_json::to_value(build_output_artifact_claim(args).unwrap()).unwrap();
    claim_json["owner"]
        .as_object_mut()
        .unwrap()
        .remove("source_snapshot");
    claim_json
        .as_object_mut()
        .unwrap()
        .remove("started_at_unix_nanos");
    fs::write(claim_path, serde_json::to_vec(&claim_json).unwrap()).unwrap();
}

fn assert_output_artifact_claim_conflict(
    expected_owner: &Options,
    conflicting_owner: &Options,
    artifact_path: &path::Path,
) {
    assert!(claim_output_artifact(expected_owner, artifact_path).unwrap());
    let err = claim_output_artifact(conflicting_owner, artifact_path)
        .err()
        .unwrap();
    assert!(err.to_string().contains("belongs to a different source"));
    release_output_artifact_claim(
        &build_output_artifact_claim(expected_owner).unwrap(),
        artifact_path,
    )
    .unwrap();
}

#[test]
fn test_publish_standalone_artifacts_finalize_source_and_executable() {
    let output_dir = TempDir::new().unwrap();
    let mut args = create_pack_test_args(&output_dir, "client.bpf.c", false);
    args.compile_opts.parameters.standalone = true;

    let invocation = OutputArtifactInvocation::start(&args).unwrap();
    let claims = claim_requested_output_artifacts_for_invocation(&invocation, &args).unwrap();
    let final_source_path = args.get_standalone_source_file_path();
    let final_executable_path = args.get_standalone_executable_path();
    let standalone_source = "int main(void) { return 0; }\n";

    publish_standalone_artifacts_for_invocation(
        &invocation,
        &args,
        standalone_source.to_string(),
        |temp_source_path, temp_executable_path| {
            assert_ne!(temp_source_path, final_source_path.as_path());
            assert_ne!(temp_executable_path, final_executable_path.as_path());
            assert!(!final_source_path.exists());
            assert!(!final_executable_path.exists());
            assert_eq!(
                fs::read_to_string(temp_source_path).unwrap(),
                standalone_source
            );
            fs::write(temp_executable_path, b"standalone-binary")?;
            Ok(())
        },
    )
    .unwrap();
    claims.release().unwrap();

    assert_eq!(
        fs::read_to_string(&final_source_path).unwrap(),
        standalone_source
    );
    assert_eq!(
        fs::read(&final_executable_path).unwrap(),
        b"standalone-binary"
    );
    assert_output_artifact_finalized(&args, &final_source_path);
    assert_output_artifact_finalized(&args, &final_executable_path);
}

#[test]
fn test_publish_wasm_header_artifact_finalizes_output() {
    let output_dir = TempDir::new().unwrap();
    let mut args = create_pack_test_args(&output_dir, "client.bpf.c", false);
    args.compile_opts.wasm_header = true;

    let invocation = OutputArtifactInvocation::start(&args).unwrap();
    let claims = claim_requested_output_artifacts_for_invocation(&invocation, &args).unwrap();
    let package_path = args.get_output_package_config_path();
    fs::write(&package_path, "{\"program\":\"value\"}").unwrap();

    publish_wasm_header_artifact_for_invocation(&invocation, &args).unwrap();
    claims.release().unwrap();

    let wasm_header = fs::read_to_string(args.get_wasm_header_path()).unwrap();
    assert!(wasm_header.contains("\\\"program\\\":\\\"value\\\""));
    assert_output_artifact_finalized(&args, args.get_wasm_header_path());
}

#[test]
fn test_pack_object_in_config_switches_package_formats_cleanly() {
    let output_dir = TempDir::new().unwrap();
    let args = create_pack_test_args(&output_dir, "client.bpf.c", false);

    fs::write(args.get_output_object_path(), b"hello world").unwrap();

    write_test_meta_config(&args);
    pack_object_in_config(&args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(!output_dir.path().join("package.yaml").exists());
    assert!(args.get_output_package_marker_path().exists());

    let yaml_args = create_pack_test_args(&output_dir, "client.bpf.c", true);
    fs::write(yaml_args.get_output_object_path(), b"hello world").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();

    assert!(yaml_args.get_output_package_config_path().exists());
    assert!(!output_dir.path().join("package.json").exists());
    assert!(!yaml_args.get_output_sibling_package_marker_path().exists());

    let json_args = create_pack_test_args(&output_dir, "client.bpf.c", false);
    fs::write(json_args.get_output_object_path(), b"hello world").unwrap();
    write_test_meta_config(&json_args);
    pack_object_in_config(&json_args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(!output_dir.path().join("package.yaml").exists());
    assert!(!json_args.get_output_sibling_package_marker_path().exists());
}

#[test]
fn test_pack_object_in_config_reused_options_use_fresh_overlap_cutoff() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);

    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();
    assert!(yaml_args.get_output_package_config_path().exists());

    thread::sleep(Duration::from_millis(2));

    fs::write(json_args.get_output_object_path(), b"json").unwrap();
    write_test_meta_config(&json_args);
    pack_object_in_config(&json_args).unwrap();

    assert!(json_args.get_output_package_config_path().exists());
    assert!(!yaml_args.get_output_package_config_path().exists());
    assert!(!json_args.get_output_sibling_package_marker_path().exists());
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
fn test_pack_object_in_config_keeps_concurrent_same_source_sibling_package() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);

    fs::write(json_args.get_output_object_path(), b"json").unwrap();
    write_test_meta_config(&json_args);
    assert!(claim_output_artifact(&json_args, json_args.get_output_package_config_path()).unwrap());
    fs::write(
        json_args.get_output_package_config_path(),
        "{\"active\":true}",
    )
    .unwrap();

    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());
    assert!(
        get_output_artifact_claim_path(&json_args, json_args.get_output_package_config_path())
            .exists()
    );
}

#[test]
fn test_pack_object_in_config_keeps_overlapping_sibling_after_first_claim_releases() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);

    assert!(claim_output_artifact(&yaml_args, yaml_args.get_output_package_config_path()).unwrap());

    fs::write(json_args.get_output_object_path(), b"json").unwrap();
    write_test_meta_config(&json_args);
    pack_object_in_config(&json_args).unwrap();

    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());

    release_output_artifact_claim(
        &build_output_artifact_claim(&yaml_args).unwrap(),
        yaml_args.get_output_package_config_path(),
    )
    .unwrap();
}

#[test]
fn test_claim_requested_output_artifacts_preserves_active_same_source_sibling_package() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let json_claims = claim_requested_output_artifacts(&json_args).unwrap();
    fs::write(json_args.get_output_object_path(), b"json").unwrap();
    write_test_meta_config(&json_args);
    pack_object_in_config(&json_args).unwrap();

    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    let yaml_claims = claim_requested_output_artifacts(&yaml_args).unwrap();
    assert!(get_output_artifact_claim_path(
        &yaml_args,
        yaml_args.get_output_sibling_package_config_path()
    )
    .exists());

    json_claims.release().unwrap();

    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();
    yaml_claims.release().unwrap();

    assert!(output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());
}

#[test]
fn test_claim_output_artifact_allows_same_source_json_yaml_shared_object() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();
    let object_path = output_dir.path().join("shared.bpf.o");

    let baseline_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);

    assert!(claim_output_artifact(&baseline_args, &object_path).unwrap());
    assert!(claim_output_artifact(&yaml_args, &object_path).unwrap());
    assert!(get_output_artifact_claim_path(&baseline_args, &object_path).exists());
    assert!(get_output_artifact_claim_path(&yaml_args, &object_path).exists());

    release_output_artifact_claim(
        &build_output_artifact_claim(&baseline_args).unwrap(),
        &object_path,
    )
    .unwrap();
    release_output_artifact_claim(
        &build_output_artifact_claim(&yaml_args).unwrap(),
        &object_path,
    )
    .unwrap();
}

#[test]
fn test_claim_output_artifact_rejects_same_source_different_build_inputs() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();
    let object_path = output_dir.path().join("shared.bpf.o");

    let baseline_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);

    let mut cflags_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    cflags_args
        .compile_opts
        .parameters
        .additional_cflags
        .push("-DOUTPUT_VARIANT=1".to_string());
    assert_output_artifact_claim_conflict(&baseline_args, &cflags_args, &object_path);

    let export_header_path = output_dir.path().join("event.h");
    fs::write(&export_header_path, "struct event { int x; };").unwrap();
    let mut export_header_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    export_header_args.compile_opts.export_event_header =
        export_header_path.to_string_lossy().to_string();
    assert_output_artifact_claim_conflict(&baseline_args, &export_header_args, &object_path);
}

#[test]
fn test_claim_output_artifact_rejects_same_path_source_revision_change() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    let object_path = output_dir.path().join("shared.bpf.o");
    fs::write(&source_path, "int x = 1;").unwrap();

    let first_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let first_claim = build_output_artifact_claim(&first_args).unwrap();
    assert!(claim_output_artifact(&first_args, &object_path).unwrap());

    fs::write(&source_path, "int x = 2;").unwrap();

    let second_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let err = claim_output_artifact(&second_args, &object_path)
        .err()
        .unwrap();
    assert!(err.to_string().contains("belongs to a different source"));

    release_output_artifact_claim(&first_claim, &object_path).unwrap();
}

#[test]
fn test_unchanged_legacy_artifact_upgrades_owner_during_finalization() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    let object_path = output_dir.path().join("shared.bpf.o");
    let legacy_object = b"legacy-object";
    fs::write(&source_path, "int x = 1;").unwrap();

    let legacy_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    fs::write(&object_path, legacy_object).unwrap();
    write_legacy_output_artifact_marker(&legacy_args, &object_path);
    write_legacy_output_artifact_claim(&legacy_args, &object_path);

    let upgrade_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    assert!(claim_output_artifact(&upgrade_args, &object_path).unwrap());

    let mut upgraded_object = create_output_object_tempfile(&object_path).unwrap();
    upgraded_object
        .as_file_mut()
        .write_all(legacy_object)
        .unwrap();
    upgraded_object.as_file_mut().sync_all().unwrap();
    assert!(!publish_output_object_artifact(&upgrade_args, upgraded_object, &object_path).unwrap());

    let upgraded_marker =
        read_output_artifact_marker(upgrade_args.get_output_artifact_marker_path(&object_path))
            .unwrap();
    assert_eq!(
        upgraded_marker.owner,
        build_output_artifact_owner(&upgrade_args).unwrap()
    );
    assert!(upgraded_marker.finalized_at_unix_nanos.is_some());

    release_output_artifact_claim(
        &build_output_artifact_claim(&upgrade_args).unwrap(),
        &object_path,
    )
    .unwrap();
    release_output_artifact_claim(
        &build_output_artifact_claim(&legacy_args).unwrap(),
        &object_path,
    )
    .unwrap();
}

#[test]
fn test_legacy_marker_and_claim_reject_changed_source_during_finalization() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    let object_path = output_dir.path().join("shared.bpf.o");
    fs::write(&source_path, "int x = 1;").unwrap();

    let legacy_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    fs::write(&object_path, b"legacy-object").unwrap();
    write_legacy_output_artifact_marker(&legacy_args, &object_path);
    write_legacy_output_artifact_claim(&legacy_args, &object_path);

    fs::write(&source_path, "int x = 2;").unwrap();

    let second_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    assert!(claim_output_artifact(&second_args, &object_path).unwrap());
    let mut rebuilt_object = create_output_object_tempfile(&object_path).unwrap();
    rebuilt_object
        .as_file_mut()
        .write_all(b"rebuilt-object")
        .unwrap();
    rebuilt_object.as_file_mut().sync_all().unwrap();
    let err = publish_output_object_artifact(&second_args, rebuilt_object, &object_path)
        .err()
        .unwrap();

    assert!(err.to_string().contains("belongs to a different source"));
    release_output_artifact_claim(
        &build_output_artifact_claim(&second_args).unwrap(),
        &object_path,
    )
    .unwrap();
    release_output_artifact_claim(
        &build_output_artifact_claim(&legacy_args).unwrap(),
        &object_path,
    )
    .unwrap();
}

#[test]
fn test_claim_output_artifact_rejects_same_path_included_header_revision_change() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    let header_path = output_dir.path().join("shared.h");
    let object_path = output_dir.path().join("shared.bpf.o");
    fs::write(&header_path, "#define SHARED_VALUE 1\n").unwrap();
    fs::write(
        &source_path,
        "#include \"shared.h\"\nint x = SHARED_VALUE;\n",
    )
    .unwrap();

    let first_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let first_claim = build_output_artifact_claim(&first_args).unwrap();
    assert!(claim_output_artifact(&first_args, &object_path).unwrap());

    fs::write(&header_path, "#define SHARED_VALUE 2\n").unwrap();

    let second_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let err = claim_output_artifact(&second_args, &object_path)
        .err()
        .unwrap();
    assert!(err.to_string().contains("belongs to a different source"));

    release_output_artifact_claim(&first_claim, &object_path).unwrap();
}

#[test]
fn test_path_resolved_tool_binaries_produce_distinct_build_identities() {
    let first_toolchain = TempDir::new().unwrap();
    let second_toolchain = TempDir::new().unwrap();

    let first_clang = first_toolchain.path().join("clang");
    let second_clang = second_toolchain.path().join("clang");
    let first_strip = first_toolchain.path().join("llvm-strip");
    let second_strip = second_toolchain.path().join("llvm-strip");

    for tool_path in [&first_clang, &second_clang, &first_strip, &second_strip] {
        fs::write(tool_path, "#!/bin/sh\n").unwrap();
    }

    let first_path_env =
        std::env::join_paths([first_toolchain.path(), std::path::Path::new("/usr/bin")]).unwrap();
    let second_path_env =
        std::env::join_paths([second_toolchain.path(), std::path::Path::new("/usr/bin")]).unwrap();

    assert_eq!(
        normalize_output_artifact_tool_identity_path_with_path_env(
            "clang",
            Some(first_path_env.as_os_str()),
        ),
        fs::canonicalize(&first_clang)
            .unwrap()
            .to_string_lossy()
            .to_string()
    );
    assert_ne!(
        normalize_output_artifact_tool_identity_path_with_path_env(
            "clang",
            Some(first_path_env.as_os_str()),
        ),
        normalize_output_artifact_tool_identity_path_with_path_env(
            "clang",
            Some(second_path_env.as_os_str()),
        )
    );
    assert_ne!(
        normalize_output_artifact_tool_identity_path_with_path_env(
            "llvm-strip",
            Some(first_path_env.as_os_str()),
        ),
        normalize_output_artifact_tool_identity_path_with_path_env(
            "llvm-strip",
            Some(second_path_env.as_os_str()),
        )
    );
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

#[test]
fn test_same_source_claims_keep_distinct_rollback_coverage() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let blocked_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let active_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let shared_artifact_path = blocked_args.get_output_package_config_path();

    assert!(claim_output_artifact(&blocked_args, &shared_artifact_path).unwrap());
    assert!(claim_output_artifact(&active_args, &shared_artifact_path).unwrap());
    assert!(get_output_artifact_claim_path(&blocked_args, &shared_artifact_path).exists());
    assert!(get_output_artifact_claim_path(&active_args, &shared_artifact_path).exists());

    let other_source_dir = TempDir::new().unwrap();
    let other_source_path = other_source_dir.path().join("shared.bpf.c");
    fs::write(&other_source_path, "int x;").unwrap();
    let blocking_owner =
        create_pack_test_args_from_source_path(&output_dir, &other_source_path, false);
    let blocked_later_artifact = blocked_args.get_standalone_executable_path();
    claim_output_artifact(&blocking_owner, &blocked_later_artifact).unwrap();

    let err = claim_output_artifact(&blocked_args, &blocked_later_artifact)
        .err()
        .unwrap();
    assert!(err.to_string().contains("belongs to a different source"));

    release_output_artifact_claim(
        &build_output_artifact_claim(&blocked_args).unwrap(),
        &shared_artifact_path,
    )
    .unwrap();

    assert!(!get_output_artifact_claim_path(&blocked_args, &shared_artifact_path).exists());
    assert!(get_output_artifact_claim_path(&active_args, &shared_artifact_path).exists());
    assert!(blocked_args
        .get_output_artifact_marker_path(&shared_artifact_path)
        .exists());
    ensure_output_artifact_can_be_written(&active_args, &shared_artifact_path).unwrap();
}

#[test]
fn test_claim_requested_output_artifacts_rolls_back_earlier_claims_on_later_collision() {
    let output_dir = TempDir::new().unwrap();
    let source_dir_a = TempDir::new().unwrap();
    let source_dir_b = TempDir::new().unwrap();
    let source_path_a = source_dir_a.path().join("shared.bpf.c");
    let source_path_b = source_dir_b.path().join("shared.bpf.c");
    fs::write(&source_path_a, "int x;").unwrap();
    fs::write(&source_path_b, "int x;").unwrap();

    let owner_args = create_pack_test_args_from_source_path(&output_dir, &source_path_a, false);
    let mut blocked_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path_b, false);
    blocked_args.compile_opts.parameters.standalone = true;

    let blocked_object_marker_path =
        blocked_args.get_output_artifact_marker_path(blocked_args.get_output_object_path());
    let blocked_config_marker_path =
        blocked_args.get_output_artifact_marker_path(blocked_args.get_output_config_path());
    let blocked_package_marker_path = blocked_args.get_output_package_marker_path();
    let blocked_standalone_source_marker_path = blocked_args
        .get_output_artifact_marker_path(blocked_args.get_standalone_source_file_path());
    let blocked_standalone_source_claim_path = get_output_artifact_claim_path(
        &blocked_args,
        blocked_args.get_standalone_source_file_path(),
    );
    let publish_entered = Arc::new(Barrier::new(2));
    let publish_release = Arc::new(Barrier::new(2));

    set_output_artifact_claim_publish_barrier(Some((
        blocked_standalone_source_claim_path,
        publish_entered.clone(),
        publish_release.clone(),
    )));

    let blocked_handle = thread::spawn(move || claim_requested_output_artifacts(&blocked_args));

    publish_entered.wait();
    claim_output_artifact(&owner_args, owner_args.get_standalone_executable_path()).unwrap();
    publish_release.wait();

    let err = blocked_handle.join().unwrap().err().unwrap();
    set_output_artifact_claim_publish_barrier(None);

    assert!(err.to_string().contains("belongs to a different source"));
    assert!(!blocked_object_marker_path.exists());
    assert!(!blocked_config_marker_path.exists());
    assert!(!blocked_package_marker_path.exists());
    assert!(!blocked_standalone_source_marker_path.exists());
    assert!(owner_args
        .get_output_artifact_marker_path(owner_args.get_standalone_executable_path())
        .exists());
}

#[test]
fn test_output_artifact_claims_guard_release_surfaces_cleanup_failures() {
    let output_dir = TempDir::new().unwrap();
    let args = create_pack_test_args(&output_dir, "client.bpf.c", false);
    let claims = claim_requested_output_artifacts(&args).unwrap();

    let injected_artifact_path = args.get_output_object_path();
    let injected_claim_path = get_output_artifact_claim_path(&args, &injected_artifact_path);
    set_output_artifact_claim_release_failure(Some((
        injected_claim_path.clone(),
        "injected release failure".to_string(),
    )));

    let err = claims.release().err().unwrap();
    set_output_artifact_claim_release_failure(None);

    assert!(err
        .to_string()
        .contains("Failed to release output artifact claims"));
    assert!(err.to_string().contains("injected release failure"));
    assert!(injected_claim_path.exists());
    assert!(args
        .get_output_artifact_marker_path(&injected_artifact_path)
        .exists());
    assert!(!args
        .get_output_artifact_marker_path(args.get_output_config_path())
        .exists());
    assert!(!args.get_output_package_marker_path().exists());

    release_output_artifact_claim(
        &build_output_artifact_claim(&args).unwrap(),
        &injected_artifact_path,
    )
    .unwrap();
}

#[test]
fn test_claim_output_artifact_keeps_claim_directory_alive_during_concurrent_publish() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let active_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let publishing_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let publishing_claim = build_output_artifact_claim(&publishing_args).unwrap();
    let artifact_path = active_args.get_output_package_config_path();
    let publishing_claim_path = get_output_artifact_claim_path(&publishing_args, &artifact_path);
    let publish_entered = Arc::new(Barrier::new(2));
    let publish_release = Arc::new(Barrier::new(2));

    assert!(claim_output_artifact(&active_args, &artifact_path).unwrap());
    set_output_artifact_claim_publish_barrier(Some((
        publishing_claim_path.clone(),
        publish_entered.clone(),
        publish_release.clone(),
    )));

    let publishing_artifact_path = artifact_path.clone();
    let publish_handle =
        thread::spawn(move || claim_output_artifact(&publishing_args, &publishing_artifact_path));

    publish_entered.wait();
    release_output_artifact_claim(
        &build_output_artifact_claim(&active_args).unwrap(),
        &artifact_path,
    )
    .unwrap();
    publish_release.wait();

    let publish_result = publish_handle.join().unwrap();
    set_output_artifact_claim_publish_barrier(None);

    assert!(publish_result.unwrap());
    assert!(publishing_claim_path.exists());
    assert!(publishing_claim_path.parent().unwrap().exists());
    assert!(active_args
        .get_output_artifact_marker_path(&artifact_path)
        .exists());

    release_output_artifact_claim(&publishing_claim, &artifact_path).unwrap();
}

#[test]
fn test_pack_object_in_config_keeps_sibling_package_during_claim_publication() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let initial_json_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    fs::write(initial_json_args.get_output_object_path(), b"json").unwrap();
    write_test_meta_config(&initial_json_args);
    pack_object_in_config(&initial_json_args).unwrap();

    let publishing_json_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let publishing_json_claim = build_output_artifact_claim(&publishing_json_args).unwrap();
    let publishing_package_path = publishing_json_args.get_output_package_config_path();
    let publishing_claim_path =
        get_output_artifact_claim_path(&publishing_json_args, &publishing_package_path);
    let publish_entered = Arc::new(Barrier::new(2));
    let publish_release = Arc::new(Barrier::new(2));

    set_output_artifact_claim_publish_barrier(Some((
        publishing_claim_path,
        publish_entered.clone(),
        publish_release.clone(),
    )));

    let publishing_handle = thread::spawn(move || {
        claim_output_artifact(&publishing_json_args, &publishing_package_path)
    });

    publish_entered.wait();

    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);
    let yaml_pack_result = pack_object_in_config(&yaml_args);

    publish_release.wait();

    let publishing_result = publishing_handle.join().unwrap();
    set_output_artifact_claim_publish_barrier(None);

    yaml_pack_result.unwrap();
    assert!(publishing_result.unwrap());
    assert!(output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());

    release_output_artifact_claim(
        &publishing_json_claim,
        output_dir.path().join("package.json"),
    )
    .unwrap();
}

#[test]
fn test_pack_object_in_config_reserves_sibling_package_during_cleanup() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let initial_json_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    fs::write(initial_json_args.get_output_object_path(), b"json").unwrap();
    write_test_meta_config(&initial_json_args);
    pack_object_in_config(&initial_json_args).unwrap();

    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);

    let competing_json_args =
        create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let cleanup_reservation_path =
        get_output_artifact_cleanup_reservation_path(output_dir.path().join("package.json"));
    let cleanup_entered = Arc::new(Barrier::new(2));
    let cleanup_release = Arc::new(Barrier::new(2));

    set_output_artifact_cleanup_reservation_barrier(Some((
        cleanup_reservation_path,
        cleanup_entered.clone(),
        cleanup_release.clone(),
    )));

    let yaml_handle = thread::spawn(move || pack_object_in_config(&yaml_args));

    cleanup_entered.wait();
    let err = claim_output_artifact(
        &competing_json_args,
        competing_json_args.get_output_package_config_path(),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("being cleaned up"));
    cleanup_release.wait();

    yaml_handle.join().unwrap().unwrap();
    set_output_artifact_cleanup_reservation_barrier(None);

    assert!(!output_dir.path().join("package.json").exists());
    assert!(output_dir.path().join("package.yaml").exists());
}

#[test]
fn test_pack_object_in_config_preserves_legacy_sibling_package_artifact() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let json_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    fs::write(
        json_args.get_output_package_config_path(),
        "{\"legacy\":true}",
    )
    .unwrap();
    write_legacy_output_artifact_marker(&json_args, json_args.get_output_package_config_path());

    let yaml_args = create_pack_test_args_from_source_path(&output_dir, &source_path, true);
    fs::write(yaml_args.get_output_object_path(), b"yaml").unwrap();
    write_test_meta_config(&yaml_args);
    pack_object_in_config(&yaml_args).unwrap();

    assert!(json_args.get_output_package_config_path().exists());
    assert!(yaml_args.get_output_package_config_path().exists());
}

#[test]
fn test_release_output_artifact_claim_reserves_cleanup_before_marker_removal() {
    let output_dir = TempDir::new().unwrap();
    let source_dir_a = TempDir::new().unwrap();
    let source_dir_b = TempDir::new().unwrap();
    let source_path_a = source_dir_a.path().join("shared.bpf.c");
    let source_path_b = source_dir_b.path().join("shared.bpf.c");
    fs::write(&source_path_a, "int x;").unwrap();
    fs::write(&source_path_b, "int x;").unwrap();

    let active_args = create_pack_test_args_from_source_path(&output_dir, &source_path_a, false);
    let competing_args = create_pack_test_args_from_source_path(&output_dir, &source_path_b, false);
    let artifact_path = active_args.get_output_package_config_path();
    let cleanup_reservation_path = get_output_artifact_cleanup_reservation_path(&artifact_path);
    let cleanup_entered = Arc::new(Barrier::new(2));
    let cleanup_release = Arc::new(Barrier::new(2));

    assert!(claim_output_artifact(&active_args, &artifact_path).unwrap());
    set_output_artifact_cleanup_reservation_barrier(Some((
        cleanup_reservation_path,
        cleanup_entered.clone(),
        cleanup_release.clone(),
    )));

    let active_claim = build_output_artifact_claim(&active_args).unwrap();
    let releasing_artifact_path = artifact_path.clone();
    let release_handle = thread::spawn(move || {
        release_output_artifact_claim(&active_claim, &releasing_artifact_path)
    });

    cleanup_entered.wait();
    let err = claim_output_artifact(&competing_args, &artifact_path)
        .err()
        .unwrap();
    assert!(err.to_string().contains("being cleaned up"));
    cleanup_release.wait();

    release_handle.join().unwrap().unwrap();
    set_output_artifact_cleanup_reservation_barrier(None);

    assert!(!active_args
        .get_output_artifact_marker_path(&artifact_path)
        .exists());
    assert!(claim_output_artifact(&competing_args, &artifact_path).unwrap());
    release_output_artifact_claim(
        &build_output_artifact_claim(&competing_args).unwrap(),
        &artifact_path,
    )
    .unwrap();
}

#[test]
fn test_claim_output_artifact_concurrent_same_source_claims_publish_complete_markers() {
    let output_dir = TempDir::new().unwrap();
    let source_path = output_dir.path().join("shared.bpf.c");
    fs::write(&source_path, "int x;").unwrap();

    let first_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let second_args = create_pack_test_args_from_source_path(&output_dir, &source_path, false);
    let artifact_path = first_args.get_output_package_config_path();
    let marker_path = first_args.get_output_artifact_marker_path(&artifact_path);

    set_output_artifact_marker_publish_barrier(Some((
        marker_path.clone(),
        Arc::new(Barrier::new(2)),
    )));

    let first_artifact_path = artifact_path.clone();
    let first_handle =
        thread::spawn(move || claim_output_artifact(&first_args, &first_artifact_path));
    let second_handle = thread::spawn(move || claim_output_artifact(&second_args, &artifact_path));

    let first_result = first_handle.join().unwrap();
    let second_result = second_handle.join().unwrap();
    set_output_artifact_marker_publish_barrier(None);

    let success_count = [first_result.as_ref(), second_result.as_ref()]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(success_count, 2);
    serde_json::from_str::<serde_json::Value>(&fs::read_to_string(marker_path).unwrap()).unwrap();
}

#[test]
fn test_claim_output_artifact_concurrent_fresh_claims_reject_other_source() {
    let output_dir = TempDir::new().unwrap();

    let first_args = create_pack_test_args(&output_dir, "first.bpf.c", false);
    let second_args = create_pack_test_args(&output_dir, "second.bpf.c", false);
    let artifact_path = first_args.get_output_package_config_path();
    let marker_path = first_args.get_output_artifact_marker_path(&artifact_path);
    let start_barrier = Arc::new(Barrier::new(3));

    let first_artifact_path = artifact_path.clone();
    let first_start_barrier = start_barrier.clone();
    let first_handle = thread::spawn(move || {
        first_start_barrier.wait();
        claim_output_artifact(&first_args, &first_artifact_path)
    });

    let second_start_barrier = start_barrier.clone();
    let second_handle = thread::spawn(move || {
        second_start_barrier.wait();
        claim_output_artifact(&second_args, &artifact_path)
    });

    start_barrier.wait();

    let first_result = first_handle.join().unwrap();
    let second_result = second_handle.join().unwrap();

    let success_count = [first_result.as_ref(), second_result.as_ref()]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(success_count, 1);
    let err = [first_result, second_result]
        .into_iter()
        .find_map(Result::err)
        .unwrap();
    assert!(err.to_string().contains("belongs to a different source"));
    serde_json::from_str::<serde_json::Value>(&fs::read_to_string(marker_path).unwrap()).unwrap();
}
