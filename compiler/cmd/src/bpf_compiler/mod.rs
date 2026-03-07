//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::bpf_compiler::standalone::build_standalone_executable;
use crate::config::{
    fetch_btfhub_repo, generate_tailored_btf, get_base_dir_include_args, get_bpf_sys_include_args,
    get_bpftool_path, get_eunomia_include_args, package_btfhub_tar, Options,
};
use crate::document_parser::parse_source_documents_with_include_base;
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

pub(crate) mod standalone;

/// compile bpf object
fn compile_bpf_object(
    args: &Options,
    source_path: impl AsRef<Path>,
    include_base_source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<()> {
    let output_path = output_path.as_ref();
    let source_path = source_path.as_ref();
    let include_base_source_path = include_base_source_path.as_ref();
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
        .args(get_base_dir_include_args(include_base_source_path)?)
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
    compile_bpf_object(
        args,
        &temp_source_file,
        &args.compile_opts.source_path,
        &output_bpf_object_path,
    )?;
    let bpf_skel_json = get_bpf_skel_json(&output_bpf_object_path, args)?;
    let bpf_skel = serde_json::from_str::<Value>(&bpf_skel_json)
        .with_context(|| anyhow!("Failed to parse json skeleton"))?;
    let bpf_skel_with_doc = match parse_source_documents_with_include_base(
        args,
        temp_source_file.as_ref().to_str().unwrap(),
        &args.compile_opts.source_path,
        bpf_skel.clone(),
    ) {
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
    let rewritten_source = rewrite_bpf_prog_macros(&source_file_content);

    let uses_temp_source =
        !args.compile_opts.export_event_header.is_empty() || rewritten_source.is_some();

    if uses_temp_source {
        temp_source_file = args.get_source_file_temp_path();
        // create temp source file
        fs::write(
            &temp_source_file,
            rewritten_source.as_deref().unwrap_or(&source_file_content),
        )?;
        if !args.compile_opts.export_event_header.is_empty() {
            add_unused_ptr_for_structs(&args.compile_opts, &temp_source_file)?;
        }
    }
    do_compile(args, &temp_source_file).with_context(|| anyhow!("Failed to compile"))?;
    if uses_temp_source {
        fs::remove_file(temp_source_file)?;
    }
    if !args.compile_opts.parameters.no_generate_package_json {
        pack_object_in_config(args).with_context(|| anyhow!("Failed to generate package json"))?;
    }
    // If we want a standalone executable..?
    if args.compile_opts.parameters.standalone {
        build_standalone_executable(args)
            .with_context(|| anyhow!("Failed to build standalone executable"))?;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceParseState {
    Code,
    LineComment,
    BlockComment,
    String,
    Char,
}

const BPF_PROG_MACRO: &str = "BPF_PROG";

fn rewrite_bpf_prog_macros(source: &str) -> Option<String> {
    let mut rewritten = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut state = SourceParseState::Code;
    let mut changed = false;
    let mut i = 0;

    while i < bytes.len() {
        match state {
            SourceParseState::Code => {
                if let Some(next_i) = advance_code_state(bytes, i, &mut state) {
                    rewritten.push_str(&source[i..next_i]);
                    i = next_i;
                } else if is_identifier_start(bytes[i]) {
                    let ident_start = i;
                    i = consume_identifier(bytes, i);
                    let ident = &source[ident_start..i];
                    if ident == BPF_PROG_MACRO {
                        if let Some(open_pos) = find_macro_open_paren(bytes, i) {
                            if let Some(close_pos) = find_matching_paren(source, open_pos) {
                                let args = &source[open_pos + 1..close_pos];
                                if let Some(rewritten_args) = rewrite_bpf_prog_arguments(args) {
                                    rewritten.push_str("BPF_PROG2(");
                                    rewritten.push_str(&rewritten_args);
                                    rewritten.push(')');
                                    changed = true;
                                } else {
                                    rewritten.push_str(&source[ident_start..=close_pos]);
                                }
                                i = close_pos + 1;
                                continue;
                            }
                        }
                    }
                    rewritten.push_str(ident);
                } else {
                    i = push_current_char(source, &mut rewritten, i);
                }
            }
            SourceParseState::LineComment => {
                let current = bytes[i];
                i = push_current_char(source, &mut rewritten, i);
                if current == b'\n' {
                    state = SourceParseState::Code;
                }
            }
            SourceParseState::BlockComment => {
                if bytes[i..].starts_with(b"*/") {
                    rewritten.push_str("*/");
                    i += 2;
                    state = SourceParseState::Code;
                } else {
                    i = push_current_char(source, &mut rewritten, i);
                }
            }
            SourceParseState::String => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    rewritten.push_str(&source[i..i + 2]);
                    i += 2;
                } else {
                    let current = bytes[i];
                    i = push_current_char(source, &mut rewritten, i);
                    if current == b'"' {
                        state = SourceParseState::Code;
                    }
                }
            }
            SourceParseState::Char => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    rewritten.push_str(&source[i..i + 2]);
                    i += 2;
                } else {
                    let current = bytes[i];
                    i = push_current_char(source, &mut rewritten, i);
                    if current == b'\'' {
                        state = SourceParseState::Code;
                    }
                }
            }
        }
    }

    changed.then_some(rewritten)
}

fn push_current_char(source: &str, rewritten: &mut String, i: usize) -> usize {
    let ch = source[i..]
        .chars()
        .next()
        .expect("source index must remain on a char boundary");
    rewritten.push(ch);
    i + ch.len_utf8()
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn consume_identifier(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() && is_identifier_continue(bytes[i]) {
        i += 1;
    }
    i
}

fn find_macro_open_paren(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
        } else if bytes[i..].starts_with(b"//") {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            if i < bytes.len() {
                i += 2;
            }
        } else {
            return (bytes[i] == b'(').then_some(i);
        }
    }
    None
}

fn find_matching_paren(source: &str, open_pos: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut state = SourceParseState::Code;
    let mut depth = 1usize;
    let mut i = open_pos + 1;

    while i < bytes.len() {
        match state {
            SourceParseState::Code => {
                if bytes[i..].starts_with(b"//") {
                    state = SourceParseState::LineComment;
                    i += 2;
                } else if bytes[i..].starts_with(b"/*") {
                    state = SourceParseState::BlockComment;
                    i += 2;
                } else {
                    match bytes[i] {
                        b'"' => {
                            state = SourceParseState::String;
                            i += 1;
                        }
                        b'\'' => {
                            state = SourceParseState::Char;
                            i += 1;
                        }
                        b'(' => {
                            depth += 1;
                            i += 1;
                        }
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(i);
                            }
                            i += 1;
                        }
                        _ => i += 1,
                    }
                }
            }
            SourceParseState::LineComment => {
                if bytes[i] == b'\n' {
                    state = SourceParseState::Code;
                }
                i += 1;
            }
            SourceParseState::BlockComment => {
                if bytes[i..].starts_with(b"*/") {
                    state = SourceParseState::Code;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            SourceParseState::String => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    if bytes[i] == b'"' {
                        state = SourceParseState::Code;
                    }
                    i += 1;
                }
            }
            SourceParseState::Char => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    if bytes[i] == b'\'' {
                        state = SourceParseState::Code;
                    }
                    i += 1;
                }
            }
        }
    }

    None
}

fn split_top_level_args(input: &str) -> Vec<&str> {
    let bytes = input.as_bytes();
    let mut state = SourceParseState::Code;
    let mut depths = DelimiterDepths::default();
    let mut start = 0usize;
    let mut parts = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        match state {
            SourceParseState::Code => {
                i = advance_split_top_level_args_code_state(
                    input,
                    bytes,
                    i,
                    &mut state,
                    &mut depths,
                    &mut start,
                    &mut parts,
                );
            }
            SourceParseState::LineComment => {
                if bytes[i] == b'\n' {
                    state = SourceParseState::Code;
                }
                i += 1;
            }
            SourceParseState::BlockComment => {
                if bytes[i..].starts_with(b"*/") {
                    state = SourceParseState::Code;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            SourceParseState::String => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    if bytes[i] == b'"' {
                        state = SourceParseState::Code;
                    }
                    i += 1;
                }
            }
            SourceParseState::Char => {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    if bytes[i] == b'\'' {
                        state = SourceParseState::Code;
                    }
                    i += 1;
                }
            }
        }
    }

    parts.push(input[start..].trim());
    parts
}

#[derive(Default)]
struct DelimiterDepths {
    paren: usize,
    brace: usize,
    bracket: usize,
}

impl DelimiterDepths {
    fn is_top_level(&self) -> bool {
        self.paren == 0 && self.brace == 0 && self.bracket == 0
    }

    fn update(&mut self, byte: u8) {
        match byte {
            b'(' => self.paren += 1,
            b')' => self.paren = self.paren.saturating_sub(1),
            b'{' => self.brace += 1,
            b'}' => self.brace = self.brace.saturating_sub(1),
            b'[' => self.bracket += 1,
            b']' => self.bracket = self.bracket.saturating_sub(1),
            _ => {}
        }
    }
}

fn advance_split_top_level_args_code_state<'a>(
    input: &'a str,
    bytes: &[u8],
    i: usize,
    state: &mut SourceParseState,
    depths: &mut DelimiterDepths,
    start: &mut usize,
    parts: &mut Vec<&'a str>,
) -> usize {
    if let Some(next_i) = advance_code_state(bytes, i, state) {
        return next_i;
    }

    if bytes[i] == b',' && depths.is_top_level() {
        parts.push(input[*start..i].trim());
        *start = i + 1;
        return i + 1;
    }

    depths.update(bytes[i]);
    i + 1
}

fn advance_code_state(bytes: &[u8], i: usize, state: &mut SourceParseState) -> Option<usize> {
    if bytes[i..].starts_with(b"//") {
        *state = SourceParseState::LineComment;
        return Some(i + 2);
    }

    if bytes[i..].starts_with(b"/*") {
        *state = SourceParseState::BlockComment;
        return Some(i + 2);
    }

    match bytes[i] {
        b'"' => {
            *state = SourceParseState::String;
            Some(i + 1)
        }
        b'\'' => {
            *state = SourceParseState::Char;
            Some(i + 1)
        }
        _ => None,
    }
}

fn rewrite_bpf_prog_arguments(args: &str) -> Option<String> {
    let parts = split_top_level_args(args);
    let (name, declarations) = parts.split_first()?;

    if declarations.is_empty() {
        return None;
    }

    let mut rewritten = vec![name.trim().to_string()];
    for declaration in declarations {
        let (arg_type, arg_name) = split_c_declaration(declaration)?;
        rewritten.push(arg_type);
        rewritten.push(arg_name);
    }
    Some(rewritten.join(", "))
}

fn split_c_declaration(declaration: &str) -> Option<(String, String)> {
    let declaration = declaration.trim();
    let bytes = declaration.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }

    let mut start = end;
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    if start == end || !bytes[start].is_ascii_alphabetic() && bytes[start] != b'_' {
        return None;
    }

    let arg_name = declaration[start..end].trim().to_string();
    let arg_type = declaration[..start].trim_end().to_string();
    if arg_type.is_empty() {
        return None;
    }

    Some((arg_type, arg_name))
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
