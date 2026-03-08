//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::bpf_compiler::standalone::build_standalone_executable;
use crate::config::{
    fetch_btfhub_repo, generate_tailored_btf, get_bpf_compile_args, get_bpftool_path,
    package_btfhub_tar, Options,
};
use crate::document_parser::parse_source_documents;
use crate::export_types::{add_unused_ptr_for_structs, find_all_export_structs};
use crate::handle_std_command_with_log;
use crate::wasm::pack_object_in_wasm_header;
use anyhow::{anyhow, bail, Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::prelude::*;
use std::path::PathBuf;
use std::{fs, path::Path};

pub(crate) mod standalone;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OutputArtifactOwner {
    object_name: String,
    source_path: String,
}

/// compile bpf object
fn compile_bpf_object(
    args: &Options,
    source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<()> {
    let output_path = output_path.as_ref();
    let source_path = source_path.as_ref();
    debug!(
        "Compiling bpf object: output: {:?}, source: {:?}",
        output_path, source_path
    );
    let clang_compile_args = get_bpf_compile_args(args, &args.compile_opts.source_path)?;
    debug!("Clang args: {:?}", clang_compile_args);

    let mut cmd = std::process::Command::new(&args.compile_opts.parameters.clang_bin);
    cmd.args(clang_compile_args)
        .arg("-c")
        .arg(source_path)
        .arg("-o")
        .arg(output_path);

    handle_std_command_with_log!(cmd, "Failed to run clang");
    let mut cmd = std::process::Command::new(&args.compile_opts.parameters.llvm_strip_bin);
    cmd.arg("-g").arg(output_path);

    handle_std_command_with_log!(cmd, "Failed to run llvm-strip");
    Ok(())
}

/// get the skel as json object
fn get_bpf_skel_json(object_path: impl AsRef<Path>, args: &Options) -> Result<String> {
    let object_path = object_path.as_ref();
    let bpftool_bin = get_bpftool_path(&args.tmpdir)?;
    let mut command = std::process::Command::new(bpftool_bin);
    command.args(["gen", "skeleton"]).arg(object_path).arg("-j");
    let output = handle_std_command_with_log!(command, "Failed to generate skeleton json");
    Ok(output)
}

/// get the export typs as json object
fn get_export_types_json(
    args: &Options,
    output_bpf_object_path: impl AsRef<Path>,
) -> Result<String> {
    let output_bpf_object_path = output_bpf_object_path.as_ref();
    let bpftool_bin = get_bpftool_path(&args.tmpdir)?;
    let mut command = std::process::Command::new(bpftool_bin);
    command
        .args(["btf", "dump", "file"])
        .arg(output_bpf_object_path)
        .args(["format", "c", "-j"]);
    let output =
        handle_std_command_with_log!(command, "Failed to dump BTF from the compiled file!");
    // filter the output to get the export types json
    let export_structs = find_all_export_structs(&args.compile_opts)?;
    let export_types_json: Value =
        serde_json::from_str(&output).with_context(|| anyhow!("Failed to parse btf json"))?;
    let export_types_json = export_types_json["structs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| {
            let name = x["name"].as_str().unwrap();
            export_structs.contains(&name.to_string())
        })
        .map(|x| x.to_owned())
        .collect::<Vec<Value>>();
    Ok(serde_json::to_string(&export_types_json).unwrap())
}

/// do actual work for compiling
fn do_compile(args: &Options, temp_source_file: impl AsRef<Path>) -> Result<()> {
    let output_bpf_object_path = args.get_output_object_path();
    let output_json_path = args.get_output_config_path();
    let mut meta_json = json!({});

    // compile bpf object
    info!("Compiling bpf object...");
    ensure_output_artifact_can_be_written(args, &output_bpf_object_path)?;
    compile_bpf_object(args, temp_source_file, &output_bpf_object_path)?;
    write_output_artifact_owner_marker(args, &output_bpf_object_path)?;
    let bpf_skel_json = get_bpf_skel_json(&output_bpf_object_path, args)?;
    let bpf_skel = serde_json::from_str::<Value>(&bpf_skel_json)
        .with_context(|| anyhow!("Failed to parse json skeleton"))?;
    let bpf_skel_with_doc =
        match parse_source_documents(args, &args.compile_opts.source_path, bpf_skel.clone()) {
            Ok(v) => v,
            Err(e) => {
                if e.to_string()
                    != "Failed to create Clang instance: an instance of `Clang` already exists"
                {
                    panic!("failed to parse source documents: {}", e);
                };
                bpf_skel
            }
        };
    meta_json["bpf_skel"] = bpf_skel_with_doc;

    // compile export types
    if !args.compile_opts.export_event_header.is_empty() {
        info!("Generating export types...");
        let export_types_json = get_export_types_json(args, &output_bpf_object_path)?;
        let export_types_json: Value = serde_json::from_str(&export_types_json)
            .with_context(|| anyhow!("Failed to parse export type json"))?;
        meta_json["export_types"] = export_types_json;
    }

    // add version
    meta_json["eunomia_version"] = json!(env!("CARGO_PKG_VERSION"));

    let meta_config_str = if args.compile_opts.yaml {
        serde_yaml::to_string(&meta_json)?
    } else {
        serde_json::to_string(&meta_json)?
    };
    ensure_output_artifact_can_be_written(args, &output_json_path)?;
    fs::write(&output_json_path, meta_config_str)?;
    write_output_artifact_owner_marker(args, &output_json_path)?;
    Ok(())
}

/// compile JSON file
pub fn compile_bpf(args: &Options) -> Result<()> {
    debug!("Compiling..");
    // backup old files
    let source_file_content = fs::read_to_string(&args.compile_opts.source_path)?;
    let mut temp_source_file = PathBuf::from(&args.compile_opts.source_path);

    if !args.compile_opts.export_event_header.is_empty() {
        temp_source_file = args.get_source_file_temp_path();
        // create temp source file
        fs::write(&temp_source_file, source_file_content)?;
        add_unused_ptr_for_structs(&args.compile_opts, &temp_source_file)?;
    }
    do_compile(args, &temp_source_file).with_context(|| anyhow!("Failed to compile"))?;
    if !args.compile_opts.export_event_header.is_empty() {
        fs::remove_file(temp_source_file)?;
    }
    if !args.compile_opts.parameters.no_generate_package_json {
        pack_object_in_config(args)
            .with_context(|| anyhow!("Failed to generate package artifact"))?;
    }
    // If we want a standalone executable..?
    if args.compile_opts.parameters.standalone {
        ensure_output_artifact_can_be_written(args, args.get_standalone_source_file_path())?;
        ensure_output_artifact_can_be_written(args, args.get_standalone_executable_path())?;
        build_standalone_executable(args)
            .with_context(|| anyhow!("Failed to build standalone executable"))?;
        write_output_artifact_owner_marker(args, args.get_standalone_source_file_path())?;
        write_output_artifact_owner_marker(args, args.get_standalone_executable_path())?;
    }
    if args.compile_opts.wasm_header {
        ensure_output_artifact_can_be_written(args, args.get_wasm_header_path())?;
        pack_object_in_wasm_header(args)
            .with_context(|| anyhow!("Failed to generate wasm header"))?;
        write_output_artifact_owner_marker(args, args.get_wasm_header_path())?;
    }
    if args.compile_opts.btfgen {
        ensure_output_artifact_can_be_written(args, args.get_output_btf_archive_directory())?;
        ensure_output_artifact_can_be_written(args, args.get_output_tar_path())?;
        fetch_btfhub_repo(&args.compile_opts)
            .with_context(|| anyhow!("Failed to fetch btfhub repo"))?;
        generate_tailored_btf(args).with_context(|| anyhow!("Failed to generate tailored btf"))?;
        write_output_artifact_owner_marker(args, args.get_output_btf_archive_directory())?;
        package_btfhub_tar(args).with_context(|| anyhow!("Failed to package btfhub tar"))?;
        write_output_artifact_owner_marker(args, args.get_output_tar_path())?;
    }
    Ok(())
}

/// Pack the object file into a generated package artifact.
fn pack_object_in_config(args: &Options) -> Result<()> {
    info!("Generating package artifact..");
    let output_bpf_object_path = args.get_output_object_path();
    let bpf_object = fs::read(output_bpf_object_path)?;

    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(&bpf_object)?;
    let compressed_bytes = e.finish().unwrap();
    let encode_bpf_object = base64::encode(compressed_bytes);
    let output_json_path = args.get_output_config_path();
    let meta_json_str = fs::read_to_string(&output_json_path).unwrap();
    let meta_json: Value = if let Ok(json) = serde_json::from_str::<Value>(&meta_json_str) {
        json
    } else {
        serde_yaml::from_str(&meta_json_str).unwrap()
    };
    let package_config = json!({
        "bpf_object": encode_bpf_object,
        "bpf_object_size": bpf_object.len(),
        "meta": meta_json,
    });
    let output_package_config_path = args.get_output_package_config_path();
    info!(
        "Packing ebpf object and config into {}...",
        output_package_config_path.display()
    );
    ensure_output_artifact_can_be_written(args, &output_package_config_path)?;
    let package_config_str = if args.compile_opts.yaml {
        serde_yaml::to_string(&package_config).unwrap()
    } else {
        serde_json::to_string(&package_config).unwrap()
    };
    fs::write(&output_package_config_path, package_config_str)?;
    write_output_artifact_owner_marker(args, &output_package_config_path)?;

    remove_matching_sibling_package_artifact(args)?;

    Ok(())
}

fn build_output_artifact_owner(args: &Options) -> OutputArtifactOwner {
    let source_path = fs::canonicalize(&args.compile_opts.source_path)
        .unwrap_or_else(|_| PathBuf::from(&args.compile_opts.source_path))
        .to_string_lossy()
        .to_string();
    OutputArtifactOwner {
        object_name: args.object_name.clone(),
        source_path,
    }
}

pub(crate) fn ensure_output_artifact_can_be_written(
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let artifact_path = artifact_path.as_ref();
    if !artifact_path.exists() {
        return Ok(());
    }

    let marker_path = args.get_output_artifact_marker_path(artifact_path);
    if !marker_path.exists() {
        bail!(
            "Refusing to overwrite existing output artifact {} because it is unclaimed; use a dedicated output directory or remove it first",
            artifact_path.display()
        );
    }

    let marker: OutputArtifactOwner = serde_json::from_str(&fs::read_to_string(&marker_path)?)?;
    if marker != build_output_artifact_owner(args) {
        bail!(
            "Refusing to overwrite existing output artifact {} because it belongs to a different source",
            artifact_path.display()
        );
    }

    Ok(())
}

pub(crate) fn write_output_artifact_owner_marker(
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let marker = build_output_artifact_owner(args);
    let marker_path = args.get_output_artifact_marker_path(artifact_path);
    fs::write(marker_path, serde_json::to_string(&marker)?)?;
    Ok(())
}

fn remove_matching_sibling_package_artifact(args: &Options) -> Result<()> {
    let sibling_package_config_path = args.get_output_sibling_package_config_path();
    if !sibling_package_config_path.exists() {
        return Ok(());
    }

    let sibling_marker_path = args.get_output_sibling_package_marker_path();
    if !sibling_marker_path.exists() {
        info!(
            "Leaving sibling package artifact {} in place because it is unclaimed",
            sibling_package_config_path.display()
        );
        return Ok(());
    }

    let sibling_marker: OutputArtifactOwner =
        serde_json::from_str(&fs::read_to_string(&sibling_marker_path)?)?;
    if sibling_marker != build_output_artifact_owner(args) {
        info!(
            "Leaving sibling package artifact {} in place because it belongs to a different source",
            sibling_package_config_path.display()
        );
        return Ok(());
    }

    info!(
        "Removing stale package artifact {}...",
        sibling_package_config_path.display()
    );
    fs::remove_file(sibling_package_config_path)?;
    fs::remove_file(sibling_marker_path)?;
    Ok(())
}

#[cfg(test)]
mod tests;
