//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::config::{
    fetch_btfhub_repo, generate_tailored_btf, get_base_dir_include, get_bpf_sys_include,
    get_bpftool_path, get_eunomia_include, get_output_config_path, get_output_object_path,
    get_source_file_temp_path, get_target_arch, package_btfhub_tar, Options,
};
use crate::document_parser::parse_source_documents;
use crate::wasm::pack_object_in_wasm_header;
use crate::{export_types::*, handle_runscrpt_with_log};
use anyhow::Result;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::{error, info};
use serde_json::{json, Value};
use std::io::prelude::*;
use std::{fs, path::Path};

fn parse_json_output(output: &str) -> Result<Value> {
    match serde_json::from_str(output) {
        Ok(v) => Ok(v),
        Err(e) => {
            error!("cannot parse json output: {}", e);
            error!("{}", output);
            Err(anyhow::anyhow!("failed to parse json output"))
        }
    }
}

/// compile bpf object
fn compile_bpf_object(args: &Options, source_path: &str, output_path: &str) -> Result<()> {
    let bpf_sys_include = get_bpf_sys_include(&args.compile_opts)?;
    let target_arch = get_target_arch();

    let command = format!(
        "{} -g -O2 -target bpf -Wno-unknown-attributes -D__TARGET_ARCH_{} {} {} {} {} -c {} -o {}",
        args.compile_opts.parameters.clang_bin,
        target_arch,
        bpf_sys_include,
        get_eunomia_include(args)?,
        args.compile_opts.parameters.additional_cflags,
        get_base_dir_include(source_path)?,
        source_path,
        output_path
    );
    handle_runscrpt_with_log!(command, "Failed to run clang");
    let command = format!(
        "{} -g {}",
        args.compile_opts.parameters.llvm_strip_bin, output_path
    );
    handle_runscrpt_with_log!(command, "Failed to run llvm-strip");

    Ok(())
}

/// get the skel as json object
fn get_bpf_skel_json(object_path: &String, args: &Options) -> Result<String> {
    let bpftool_bin = get_bpftool_path(&args.tmpdir)?;
    let command = format!("{} gen skeleton {} -j", bpftool_bin, object_path);
    let output = handle_runscrpt_with_log!(command, "Failed to generate skeleton json");
    Ok(output)
}

/// get the export typs as json object
fn get_export_types_json(args: &Options, output_bpf_object_path: &String) -> Result<String> {
    let bpftool_bin = get_bpftool_path(&args.tmpdir)?;
    let command = format!(
        "{} btf dump file {} format c -j",
        bpftool_bin, output_bpf_object_path
    );
    // let (code, output, error) = run_script::run_script!(command).unwrap();

    // handle_runscript_output!(code, command, output, error, "Failed to compile bpf object");
    let output = handle_runscrpt_with_log!(command, "Failed to dump BTF from the compiler file!");
    // fiter the output to get the export types json
    let export_structs = find_all_export_structs(&args.compile_opts)?;
    let export_types_json: Value = parse_json_output(&output).unwrap();
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
fn do_compile(args: &Options, temp_source_file: &str) -> Result<()> {
    let output_bpf_object_path = get_output_object_path(args);
    let output_json_path = get_output_config_path(args);
    let mut meta_json = json!({});

    // compile bpf object
    info!("Compiling bpf object...");
    compile_bpf_object(args, temp_source_file, &output_bpf_object_path)?;
    let bpf_skel_json = get_bpf_skel_json(&output_bpf_object_path, args)?;
    let bpf_skel = parse_json_output(&bpf_skel_json)?;
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
        let export_types_json: Value = parse_json_output(&export_types_json)?;
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
    // backup old files
    let source_file_content = fs::read_to_string(&args.compile_opts.source_path)?;
    let mut temp_source_file = args.compile_opts.source_path.clone();

    if !args.compile_opts.export_event_header.is_empty() {
        temp_source_file = get_source_file_temp_path(args);
        // create temp source file
        fs::write(&temp_source_file, source_file_content)?;
        add_unused_ptr_for_structs(&args.compile_opts, &temp_source_file)?;
    }
    let res = do_compile(args, &temp_source_file);
    if !args.compile_opts.export_event_header.is_empty() {
        fs::remove_file(temp_source_file)?;
    }
    if args.compile_opts.parameters.generate_package_json {
        pack_object_in_config(args).unwrap();
    }
    if args.compile_opts.wasm_header {
        pack_object_in_wasm_header(args).unwrap();
    }
    if args.compile_opts.btfgen {
        fetch_btfhub_repo(&args.compile_opts).unwrap();
        generate_tailored_btf(args).unwrap();
        package_btfhub_tar(args).unwrap();
    }
    res
}

/// pack the object file into a package.json
fn pack_object_in_config(args: &Options) -> Result<()> {
    let output_bpf_object_path = get_output_object_path(args);
    let bpf_object = fs::read(output_bpf_object_path)?;

    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(&bpf_object)?;
    let compressed_bytes = e.finish().unwrap();
    let encode_bpf_object = base64::encode(compressed_bytes);
    let output_json_path = get_output_config_path(args);
    let meta_json_str = fs::read_to_string(&output_json_path).unwrap();
    let meta_json: Value = if let Ok(json) = parse_json_output(&meta_json_str) {
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
