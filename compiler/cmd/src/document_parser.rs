//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
extern crate clang;
use std::path::Path;
use std::result::Result::Ok;

use crate::config::get_base_dir_include_args;
use crate::config::get_bpf_sys_include_args;
use crate::config::get_eunomia_include_args;
use crate::config::Options;
use crate::helper::get_target_arch;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clang::documentation::CommentChild;
use clang::Clang;
use clang::Entity;
use clang::EntityKind;
use clang::Index;
use clang::TranslationUnit;
use log::warn;
use serde_json::{json, Value};

fn parse_source_files<'a>(
    index: &'a Index<'a>,
    args: &'a Options,
    source_path: &'a Path,
) -> Result<TranslationUnit<'a>> {
    let bpf_sys_include = get_bpf_sys_include_args(&args.compile_opts)?;
    let target_arch = get_target_arch();
    let target_arch = format!("-D__TARGET_ARCH_{target_arch}");
    let eunomia_include = get_eunomia_include_args(args)?;
    let base_dir_include = get_base_dir_include_args(source_path)?;
    let mut compile_args = vec![
        "-g".to_string(),
        "-O2".to_string(),
        "-target bpf".to_string(),
        "-Wno-unknown-attributes".to_string(),
        target_arch,
    ];
    compile_args.extend(bpf_sys_include);
    compile_args.extend(eunomia_include);
    compile_args.extend(base_dir_include);
    compile_args.extend(args.compile_opts.parameters.additional_cflags.clone());

    // Parse a source file into a translation unit
    let tu = index
        .parser(source_path)
        .arguments(&compile_args)
        .parse()
        .with_context(|| anyhow!("Failed to build translation unit"))?;
    Ok(tu)
}

fn process_comment_child(child: CommentChild, value: &mut Value, default_cmd: &str) {
    match child {
        CommentChild::Paragraph(text) => {
            let mut cmd = String::from(default_cmd);
            for child in text {
                match child {
                    CommentChild::InlineCommand(command) => {
                        cmd = command.command;
                    }
                    _ => {
                        process_comment_child(child, value, &cmd);
                    }
                }
            }
        }
        CommentChild::Text(text) => {
            let text = text.trim();
            // skip blank text
            if text.is_empty() {
                return;
            }
            value[&default_cmd] = match serde_json::from_str::<Value>(text) {
                Ok(v) => v,
                Err(_) => {
                    // if text is not json, use it as string
                    warn!("warning: text is not json: {}", text);
                    warn!(" use it as a string");
                    json!(&text)
                }
            };
        }
        CommentChild::InlineCommand(command) => {
            value[&command.command] = json!(true);
        }
        CommentChild::BlockCommand(command) => {
            let mut text = String::default();
            for child in command.children {
                if let CommentChild::Text(t) = child {
                    text.push_str(&t);
                    text.push('\n');
                }
            }
            text = text.trim().to_string();
            value[&command.command] = json!(text);
        }
        _ => {}
    }
}

/// reslove bpf global variables
fn resolve_section_data_entities(entities: &Vec<Entity>, data_sec: &mut Value) {
    for var in data_sec["variables"].as_array_mut().unwrap() {
        for e in entities {
            if e.get_kind() != EntityKind::VarDecl {
                continue;
            }
            let name = if let Some(name) = e.get_name() {
                name
            } else {
                continue;
            };
            if name != var["name"].as_str().unwrap() {
                continue;
            }
            if let Some(comment) = e.get_parsed_comment() {
                let children = comment.get_children();
                for child in children {
                    process_comment_child(child, var, "description");
                }
            }
        }
    }
}

/// reslove bpf maps comments
fn resolve_map_entities(entities: &Vec<Entity>, map: &mut Value) {
    let mut last_var_entity = None;
    for e in entities {
        if e.get_kind() != EntityKind::VarDecl || last_var_entity.is_none() {
            last_var_entity = Some(e);
            continue;
        }
        let name = if let Some(name) = e.get_name() {
            name
        } else {
            last_var_entity = Some(e);
            continue;
        };
        if name != map["name"].as_str().unwrap() {
            last_var_entity = Some(e);
            continue;
        }
        // for maps like:
        //
        // /// @sample {"interval": 1000}
        // struct {
        //     __uint(type, BPF_MAP_TYPE_HASH);
        //     __uint(max_entries, 8192);
        //     __type(key, pid_t);
        //     __type(value, u64);
        // } exec_start SEC(".maps");
        //
        // we need to extract comments from the type declaration
        if let Some(comment) = last_var_entity.unwrap().get_parsed_comment() {
            let children = comment.get_children();
            for child in children {
                process_comment_child(child, map, "description");
            }
        }
        last_var_entity = Some(e);
    }
}

/// reslove bpf progs comments
fn resolve_progs_entities(entities: &Vec<Entity>, progs: &mut Value) {
    for e in entities {
        if e.get_kind() != EntityKind::FunctionDecl {
            continue;
        }
        let name = if let Some(name) = e.get_name() {
            name
        } else {
            continue;
        };
        if name != progs["name"].as_str().unwrap() {
            continue;
        }
        if let Some(comment) = e.get_parsed_comment() {
            let children = comment.get_children();
            for child in children {
                process_comment_child(child, progs, "description");
            }
        }
    }
}

/// parse the doc in LICENSE comment
fn resolve_doc_entities(entities: &Vec<Entity>, skel_json: &mut Value) {
    for e in entities {
        if e.get_kind() != EntityKind::VarDecl {
            continue;
        }
        let name = if let Some(name) = e.get_name() {
            name
        } else {
            continue;
        };
        if name != "LICENSE" {
            continue;
        }
        if let Some(comment) = e.get_parsed_comment() {
            let children = comment.get_children();
            let mut value = json!({});
            for child in children {
                process_comment_child(child, &mut value, "description");
            }
            skel_json["doc"] = value;
        }
    }
}

fn resolve_bpf_skel_entities(entities: &Vec<Entity>, bpf_skel_json: Value) -> Result<Value> {
    let mut new_skel_json = bpf_skel_json;
    if let Some(data_secs) = new_skel_json["data_sections"].as_array_mut() {
        // resolve comments for section data
        for data_sec in data_secs {
            resolve_section_data_entities(entities, data_sec);
        }
    }
    if let Some(map_secs) = new_skel_json["maps"].as_array_mut() {
        // resolve comments for section maps
        for map_sec in map_secs {
            resolve_map_entities(entities, map_sec);
        }
    }
    if let Some(progs_secs) = new_skel_json["progs"].as_array_mut() {
        // resolve comments for section progs
        for progs_sec in progs_secs {
            resolve_progs_entities(entities, progs_sec);
        }
    }
    resolve_doc_entities(entities, &mut new_skel_json);
    Ok(new_skel_json)
}

/// Get documentations from source file
pub fn parse_source_documents(
    args: &Options,
    source_path: &str,
    bpf_skel_json: Value,
) -> Result<Value> {
    // Acquire an instance of `Clang`
    let clang = match Clang::new() {
        Ok(clang) => clang,
        Err(e) => {
            return Err(anyhow!("Failed to create Clang instance: {}", e));
        }
    };
    // Create a new `Index`
    let index = Index::new(&clang, false, true);
    let _source_path = Path::new(source_path);
    let canonic_source_path = _source_path.canonicalize().unwrap();
    let tu = parse_source_files(&index, args, &canonic_source_path)?;

    // Get the entities in this translation unit
    let entities = tu
        .get_entity()
        .get_children()
        .into_iter()
        .filter(|e| {
            if let Some(location) = e.get_location() {
                if let Some(file) = location.get_file_location().file {
                    if file.get_path() == canonic_source_path {
                        return true;
                    }
                }
            }
            false
        })
        .collect::<Vec<_>>();

    // reslove comments for section data and functions, maps
    // find the entity with the same name as the names in the json skeleton
    let new_skel_json = resolve_bpf_skel_entities(&entities, bpf_skel_json)?;
    Ok(new_skel_json)
}

#[cfg(test)]
mod test {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use serde_json::json;
    use tempfile::TempDir;

    use crate::config::{init_eunomia_workspace, CompileArgs, Options};

    use super::parse_source_documents;

    const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";

    fn create_args() -> Options {
        let tmp_workspace = TempDir::new().unwrap();
        init_eunomia_workspace(&tmp_workspace).unwrap();
        let tmp_dir = Path::new(TEMP_EUNOMIA_DIR);
        let tmp_dir = tmp_dir.join("test_compile_bpf");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(
            tmp_dir.join("other_header.h"),
            include_str!("../test/other_header.h"),
        )
        .unwrap();
        let source_path = tmp_dir.join("client.bpf.c");
        fs::write(&source_path, include_str!("../test/client.bpf.c")).unwrap();
        let event_path = tmp_dir.join("event.h");
        fs::write(&event_path, include_str!("../test/event.h")).unwrap();
        Options {
            tmpdir: tmp_workspace,
            compile_opts: CompileArgs {
                source_path: source_path.to_str().unwrap().to_string(),
                ..Default::default()
            },
            object_name: PathBuf::from(source_path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        }
    }

    #[test]
    fn test_parse_variables() {
        let args = create_args();

        let test_case_res = json!({
            "name": ".rodata",
            "variables": [
                {
                    "description": "min duration for a process to be considered",
                    "name": "min_duration_ns",
                    "type": "unsigned long long"
                },
                {
                    "cmdarg":{
                        "default": 0,
                        "short": "p",
                        "long": "pid",
                    },
                    "description": "target pid to trace",
                    "name": "target_pid",
                    "type": "int"
                }
            ]
        });
        let skel = parse_source_documents(
            &args,
            args.compile_opts.source_path.as_str(),
            json!({"data_sections": [
                {
                    "name": ".rodata",
                    "variables": [
                        {
                            "name": "min_duration_ns",
                            "type": "unsigned long long"
                        },
                        {
                            "name": "target_pid",
                            "type": "int"
                        }
                    ]
                }
            ],
            "maps":[], "progs":[]}),
        );
        let skel = match skel {
            Ok(skel) => skel,
            Err(e) => {
                if e.to_string()
                    != "Failed to create Clang instance: an instance of `Clang` already exists"
                {
                    panic!("failed to parse source documents: {}", e);
                }
                return;
            }
        };
        let rodata = &skel["data_sections"][0];
        assert_eq!(rodata, &test_case_res);
    }

    #[test]
    fn test_parse_progss() {
        let args = create_args();
        let test_case_res = json!([{
            "attach": "tp/sched/sched_process_exec",
            "link": true,
            "name": "handle_exec",
            "flag":"called when a process starts"
        },
        {
            "attach": "tp/sched/sched_process_exit",
            "description": "called when a process ends",
            "link": true,
            "name": "handle_exit",
        }]);
        let skel = parse_source_documents(
            &args,
            args.compile_opts.source_path.as_str(),
            json!({"progs": [
                {
                    "attach": "tp/sched/sched_process_exec",
                    "link": true,
                    "name": "handle_exec"
                },
                {
                    "attach": "tp/sched/sched_process_exit",
                    "link": true,
                    "name": "handle_exit"
                }
            ],"maps":[], "data_sections":[]}),
        );
        let skel = match skel {
            Ok(skel) => skel,
            Err(e) => {
                if e.to_string()
                    != "Failed to create Clang instance: an instance of `Clang` already exists"
                {
                    panic!("failed to parse source documents: {}", e);
                }
                return;
            }
        };
        let handle_exec = &skel["progs"];
        assert_eq!(handle_exec, &test_case_res);
    }

    #[test]
    fn test_parse_maps() {
        let test_case_res = json!({
            "ident": "exec_start",
            "name": "exec_start",
            "sample": {"interval": 1000}
        });
        let args = create_args();
        let skel = parse_source_documents(
            &args,
            args.compile_opts.source_path.as_str(),
            json!({"maps": [
                {
                    "ident": "exec_start",
                    "name": "exec_start",
                }
            ], "progs":[], "data_sections":[]}),
        );
        let skel = match skel {
            Ok(skel) => skel,
            Err(e) => {
                if e.to_string()
                    != "Failed to create Clang instance: an instance of `Clang` already exists"
                {
                    panic!("failed to parse source documents: {}", e);
                }
                return;
            }
        };
        let exec_start = &skel["maps"][0];
        assert_eq!(exec_start, &test_case_res);
    }

    #[test]
    fn test_parse_empty() {
        let args = create_args();
        let _ = parse_source_documents(&args, args.compile_opts.source_path.as_str(), json!({}));
    }
}
