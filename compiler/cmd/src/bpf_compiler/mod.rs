//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::config::{
    fetch_btfhub_repo, generate_tailored_btf, get_base_dir_include_args, get_bpf_sys_include_args,
    get_bpftool_path, get_eunomia_include_args, package_btfhub_tar, Options,
};
use crate::document_parser::parse_source_documents;
use crate::export_types::{add_unused_ptr_for_structs, find_all_export_structs};
use crate::handle_std_command_with_log;
use crate::helper::get_target_arch;
use crate::wasm::pack_object_in_wasm_header;
use anyhow::{anyhow, bail, Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::{debug, info};
use serde_json::{json, Value};
use std::io::prelude::*;
use std::path::PathBuf;
use std::{fs, path::Path};

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
    let bpf_sys_include = get_bpf_sys_include_args(&args.compile_opts)?;
    debug!("Sys include: {:?}", bpf_sys_include);
    let target_arch = get_target_arch();

    let mut cmd = std::process::Command::new(&args.compile_opts.parameters.clang_bin);
    cmd.args(["-g", "-O2", "-target", "bpf", "-Wno-unknown-attributes"])
        .arg(format!("-D__TARGET_ARCH_{}", target_arch))
        .args(bpf_sys_include)
        .args(get_eunomia_include_args(args)?)
        .args(&args.compile_opts.parameters.additional_cflags)
        .args(get_base_dir_include_args(source_path)?)
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
    compile_bpf_object(args, temp_source_file, &output_bpf_object_path)?;
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
    fs::write(output_json_path, meta_config_str)?;
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
    if args.compile_opts.parameters.generate_package_json {
        pack_object_in_config(args).with_context(|| anyhow!("Failed to generate package json"))?;
    }
    // If we want a standalone executable..?
    if args.compile_opts.parameters.standalone {
        // let package_json_bytes = std::fs::read(get)
    }
    if args.compile_opts.wasm_header {
        pack_object_in_wasm_header(args)
            .with_context(|| anyhow!("Failed to generate wasm header"))?;
    }
    if args.compile_opts.btfgen {
        fetch_btfhub_repo(&args.compile_opts)
            .with_context(|| anyhow!("Failed to fetch btfhub repo"))?;
        generate_tailored_btf(args).with_context(|| anyhow!("Failed to generate tailored btf"))?;
        package_btfhub_tar(args).with_context(|| anyhow!("Failed to package btfhub tar"))?;
    }
    Ok(())
}

/// pack the object file into a package.json
fn pack_object_in_config(args: &Options) -> Result<()> {
    info!("Generating package json..");
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
    if args.compile_opts.yaml {
        let output_package_config_path = Path::new(&output_json_path)
            .parent()
            .unwrap()
            .join("package.yaml");
        info!(
            "Packing ebpf object and config into {}...",
            output_package_config_path.display()
        );
        let package_config_str = serde_yaml::to_string(&package_config).unwrap();
        fs::write(output_package_config_path, package_config_str)?;
    } else {
        let output_package_config_path = Path::new(&output_json_path)
            .parent()
            .unwrap()
            .join("package.json");
        info!(
            "Packing ebpf object and config into {}...",
            output_package_config_path.display()
        );
        let package_config_str = serde_json::to_string(&package_config).unwrap();
        fs::write(output_package_config_path, package_config_str)?;
    };
    Ok(())
}

#[cfg(test)]
mod tests;
