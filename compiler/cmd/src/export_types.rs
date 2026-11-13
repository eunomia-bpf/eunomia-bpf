//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{collections::HashSet, fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use clang::{Entity, EntityKind, Index};
use serde_json::Value;

use crate::{
    config::{get_bpf_compile_args, Options},
    helper::with_clang,
};

const _EXPORT_C_TEMPLATE: &str = r#"
// do not use this file: auto generated
#include "vmlinux.h"

// make the compiler not ignore event struct
// generate BTF event struct

"#;

const DUMMY_PTR_PREFIX: &str = "__eunomia_dummy_";
const EXPORT_ANNOTATION: &str = "@export";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportStructCandidate {
    name: String,
    explicit: bool,
}

fn same_source_file(actual_path: &Path, expected_path: &Path) -> bool {
    if actual_path == expected_path {
        return true;
    }
    match (actual_path.canonicalize(), expected_path.canonicalize()) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    }
}

fn entity_is_in_file(entity: &Entity, expected_path: &Path) -> bool {
    entity
        .get_location()
        .and_then(|location| location.get_file_location().file)
        .map(|file| same_source_file(&file.get_path(), expected_path))
        .unwrap_or(false)
}

fn trim_comment_marker(line: &str) -> &str {
    let line = line.trim();
    let line = line
        .strip_prefix("///")
        .or_else(|| line.strip_prefix("//!"))
        .or_else(|| line.strip_prefix("/**"))
        .or_else(|| line.strip_prefix("/*"))
        .or_else(|| line.strip_prefix('*'))
        .unwrap_or(line)
        .trim();
    line.strip_suffix("*/").unwrap_or(line).trim()
}

fn has_export_annotation(entity: &Entity) -> bool {
    entity
        .get_comment()
        .map(|comment| {
            comment
                .lines()
                .map(trim_comment_marker)
                .any(|line| line == EXPORT_ANNOTATION)
        })
        .unwrap_or(false)
}

fn push_export_struct(candidates: &mut Vec<ExportStructCandidate>, name: String, explicit: bool) {
    if let Some(existing) = candidates
        .iter_mut()
        .find(|candidate| candidate.name == name)
    {
        existing.explicit |= explicit;
    } else {
        candidates.push(ExportStructCandidate { name, explicit });
    }
}

fn dummy_ptr_symbol_name(struct_name: &str) -> String {
    format!("{DUMMY_PTR_PREFIX}{struct_name}_ptr")
}

fn collect_export_struct_candidates(args: &Options) -> Result<Vec<ExportStructCandidate>> {
    let source_path = Path::new(&args.compile_opts.source_path).to_path_buf();
    let export_header_path = Path::new(&args.compile_opts.export_event_header).to_path_buf();

    with_clang(|clang| {
        let index = Index::new(clang, false, true);
        let compile_args = get_bpf_compile_args(args, &source_path)?;
        let tu = index
            .parser(&source_path)
            .arguments(&compile_args)
            .parse()
            .with_context(|| anyhow!("Failed to build translation unit for export types"))?;
        let mut candidates = Vec::new();

        for entity in tu.get_entity().get_children() {
            if !entity_is_in_file(&entity, &export_header_path) {
                continue;
            }
            match entity.get_kind() {
                EntityKind::StructDecl if entity.is_definition() => {
                    if let Some(name) = entity.get_name() {
                        push_export_struct(&mut candidates, name, has_export_annotation(&entity));
                    }
                }
                EntityKind::TypedefDecl => {
                    let Some(struct_decl) = entity
                        .get_typedef_underlying_type()
                        .and_then(|ty| ty.get_declaration())
                    else {
                        continue;
                    };
                    if struct_decl.get_kind() != EntityKind::StructDecl
                        || !struct_decl.is_definition()
                        || !entity_is_in_file(&struct_decl, &export_header_path)
                    {
                        continue;
                    }
                    let Some(name) = struct_decl.get_name() else {
                        continue;
                    };
                    push_export_struct(
                        &mut candidates,
                        name,
                        has_export_annotation(&entity) || has_export_annotation(&struct_decl),
                    );
                }
                _ => {}
            }
        }

        Ok(candidates)
    })
}

/// Select named struct definitions from the designated export header.
/// If any struct is annotated with `@export`, only annotated structs are exported.
/// Otherwise all named struct definitions are exported for backward compatibility.
pub fn find_all_export_structs(args: &Options) -> Result<Vec<String>> {
    let candidates = collect_export_struct_candidates(args)?;
    if candidates.iter().any(|candidate| candidate.explicit) {
        Ok(candidates
            .into_iter()
            .filter(|candidate| candidate.explicit)
            .map(|candidate| candidate.name)
            .collect())
    } else {
        Ok(candidates
            .into_iter()
            .map(|candidate| candidate.name)
            .collect())
    }
}

/// add unused_ptr_for_structs to preserve BTF info
/// optional: add  __attribute__((preserve_access_index)) for structs to preserve BTF info
pub fn add_unused_ptr_for_structs(args: &Options, file_path: impl AsRef<Path>) -> Result<()> {
    let file_path = file_path.as_ref();
    let export_struct_names = find_all_export_structs(args)?;
    let content = fs::read_to_string(file_path);
    let mut content = match content {
        Ok(content) => content,
        Err(e) => {
            bail!("Failed to access file {:?}, {}", file_path, e);
        }
    };

    for struct_name in export_struct_names {
        let dummy_symbol_name = dummy_ptr_symbol_name(&struct_name);
        content += &format!(
            "const volatile struct {} * {}  __attribute__((unused));\n",
            struct_name, dummy_symbol_name
        );
    }
    fs::write(file_path, content)?;
    Ok(())
}

pub fn get_synthetic_bpf_skel_symbols(args: &Options) -> Result<HashSet<String>> {
    if args.compile_opts.export_event_header.is_empty() {
        return Ok(HashSet::new());
    }
    Ok(find_all_export_structs(args)?
        .into_iter()
        .map(|struct_name| dummy_ptr_symbol_name(&struct_name))
        .collect())
}

pub fn strip_synthetic_bpf_skel_symbols(
    mut bpf_skel: Value,
    synthetic_symbols: &HashSet<String>,
) -> Value {
    if synthetic_symbols.is_empty() {
        return bpf_skel;
    }

    let mut removed_section_names = HashSet::new();
    let mut removed_section_idents = HashSet::new();
    if let Some(data_sections) = bpf_skel["data_sections"].as_array_mut() {
        for data_section in data_sections.iter_mut() {
            if let Some(variables) = data_section["variables"].as_array_mut() {
                let variable_count = variables.len();
                variables.retain(|variable| {
                    variable["name"]
                        .as_str()
                        .map(|name| !synthetic_symbols.contains(name))
                        .unwrap_or(true)
                });
                if variable_count != variables.len() && variables.is_empty() {
                    if let Some(section_name) = data_section["name"].as_str() {
                        removed_section_names.insert(section_name.to_string());
                        if let Some(ident) = section_name.strip_prefix('.') {
                            removed_section_idents.insert(ident.to_string());
                        }
                    }
                }
            }
        }
        data_sections.retain(|data_section| {
            data_section["name"]
                .as_str()
                .map(|section_name| !removed_section_names.contains(section_name))
                .unwrap_or(true)
        });
    }
    if let Some(maps) = bpf_skel["maps"].as_array_mut() {
        maps.retain(|map| {
            let mmaped = map["mmaped"].as_bool().unwrap_or(false);
            let ident = map["ident"].as_str().unwrap_or_default();
            !(mmaped && removed_section_idents.contains(ident))
        });
    }
    bpf_skel
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::os::unix::fs::symlink;
    use std::{fs, path::Path};

    use clap::Parser;
    use serde_json::json;
    use tempfile::TempDir;

    use super::{
        add_unused_ptr_for_structs, find_all_export_structs, strip_synthetic_bpf_skel_symbols,
    };
    use crate::config::{init_eunomia_workspace, CompileArgs, Options};

    fn create_options(
        source_path: &Path,
        export_header_path: Option<&Path>,
        header_only: bool,
    ) -> Options {
        let tmp_workspace = TempDir::new().unwrap();
        init_eunomia_workspace(&tmp_workspace).unwrap();

        let mut argv = vec!["ecc".to_string(), source_path.to_str().unwrap().to_string()];
        if let Some(export_header_path) = export_header_path {
            argv.push(export_header_path.to_str().unwrap().to_string());
        }
        if header_only {
            argv.push("--header-only".to_string());
        }

        Options::init(CompileArgs::try_parse_from(argv).unwrap(), tmp_workspace).unwrap()
    }

    #[test]
    fn test_find_all_export_structs_ignores_comments_and_if0() {
        let temp_dir = TempDir::new().unwrap();
        let header_path = temp_dir.path().join("event.h");
        let source_path = temp_dir.path().join("test.bpf.c");
        let test_event = r#"
            struct eventqwrd3 { int x; };
            /* struct commented_out { int x; }; */
            #if 0
            struct disabled { int x; };
            #endif
            typedef struct event3 { int x; } event3_t;
        "#;
        fs::write(&header_path, test_event).unwrap();
        fs::write(&source_path, "#include \"event.h\"\n").unwrap();

        let opts = create_options(&source_path, Some(&header_path), false);
        let structs = find_all_export_structs(&opts).unwrap();

        assert_eq!(structs, vec!["eventqwrd3", "event3"]);
    }

    #[test]
    fn test_find_all_export_structs_prefers_export_annotations() {
        let temp_dir = TempDir::new().unwrap();
        let header_path = temp_dir.path().join("event.h");
        let source_path = temp_dir.path().join("test.bpf.c");
        let test_event = r#"
            struct helper { int x; };
            /// @export
            typedef struct event3 { int x; } event3_t;
            struct event2 { int x; };
        "#;
        fs::write(&header_path, test_event).unwrap();
        fs::write(&source_path, "#include \"event.h\"\n").unwrap();

        let opts = create_options(&source_path, Some(&header_path), false);
        let structs = find_all_export_structs(&opts).unwrap();

        assert_eq!(structs, vec!["event3"]);
    }

    #[test]
    fn test_find_all_export_structs_ignores_export_mentions_in_prose() {
        let temp_dir = TempDir::new().unwrap();
        let header_path = temp_dir.path().join("event.h");
        let source_path = temp_dir.path().join("test.bpf.c");
        let test_event = r#"
            /// This helper mentions @export in prose but is not annotated.
            struct helper { int x; };
            struct event { int x; };
        "#;
        fs::write(&header_path, test_event).unwrap();
        fs::write(&source_path, "#include \"event.h\"\n").unwrap();

        let opts = create_options(&source_path, Some(&header_path), false);
        let structs = find_all_export_structs(&opts).unwrap();

        assert_eq!(structs, vec!["helper", "event"]);
    }

    #[test]
    fn test_add_unused_ptr_for_structs() {
        let temp_dir = TempDir::new().unwrap();
        let header_path = temp_dir.path().join("event.h");
        let source_path = temp_dir.path().join("test.bpf.c");
        let tmp_source_file = temp_dir.path().join("tmp_test_event.c");
        let test_event = r#"
            struct helper { int x; };
            /// @export
            struct event2 { int x; };
            /// @export
            typedef struct event3 { int x; } event3_t;
        "#;
        let test_source_content_res = "const volatile struct event2 * __eunomia_dummy_event2_ptr  __attribute__((unused));\nconst volatile struct event3 * __eunomia_dummy_event3_ptr  __attribute__((unused));\n";
        fs::write(&header_path, test_event).unwrap();
        fs::write(&source_path, "#include \"event.h\"\n").unwrap();
        fs::write(&tmp_source_file, "").unwrap();

        let opts = create_options(&source_path, Some(&header_path), false);
        add_unused_ptr_for_structs(&opts, &tmp_source_file).unwrap();

        let content = fs::read_to_string(&tmp_source_file).unwrap();
        assert_eq!(test_source_content_res, content);
    }

    #[test]
    fn test_find_all_export_structs_header_only_uses_source_header() {
        let temp_dir = TempDir::new().unwrap();
        let header_path = temp_dir.path().join("event.h");
        let test_event = r#"
            /// @export
            struct event4 { int x; };
        "#;
        fs::write(&header_path, test_event).unwrap();

        let opts = create_options(&header_path, None, true);
        let structs = find_all_export_structs(&opts).unwrap();

        assert_eq!(structs, vec!["event4"]);
    }

    #[test]
    fn test_find_all_export_structs_header_only_keeps_symlink_include_root() {
        let temp_dir = TempDir::new().unwrap();
        let real_dir = temp_dir.path().join("real");
        let symlink_dir = temp_dir.path().join("link");
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(&symlink_dir).unwrap();

        let real_header_path = real_dir.join("event.h");
        let symlink_header_path = symlink_dir.join("event.h");
        fs::write(
            &real_header_path,
            r#"
                #include "shared.h"
                /// @export
                struct event { shared_int_t x; };
            "#,
        )
        .unwrap();
        fs::write(symlink_dir.join("shared.h"), "typedef int shared_int_t;\n").unwrap();
        symlink(&real_header_path, &symlink_header_path).unwrap();

        let opts = create_options(&symlink_header_path, None, true);
        let structs = find_all_export_structs(&opts).unwrap();

        assert_eq!(structs, vec!["event"]);
    }

    #[test]
    fn test_strip_synthetic_bpf_skel_symbols_only_removes_exact_dummy_matches() {
        let original = json!({
            "data_sections": [
                {
                    "name": ".rodata",
                    "variables": [
                        { "name": "__eunomia_dummy_user_setting" },
                        { "name": "__eunomia_dummy_selected_event_ptr" },
                        { "name": "__eunomia_dummy_selected_event_ptr_user" }
                    ]
                },
                {
                    "name": ".bss",
                    "variables": [
                        { "name": "kept" }
                    ]
                }
            ],
            "maps": [
                { "ident": "rodata", "mmaped": true },
                { "ident": "bss", "mmaped": true }
            ]
        });

        assert_eq!(
            strip_synthetic_bpf_skel_symbols(original.clone(), &HashSet::new()),
            original
        );

        let stripped = strip_synthetic_bpf_skel_symbols(
            original,
            &HashSet::from(["__eunomia_dummy_selected_event_ptr".to_string()]),
        );

        let variables = stripped["data_sections"][0]["variables"]
            .as_array()
            .unwrap();
        assert_eq!(variables.len(), 2);
        assert_eq!(
            variables[0]["name"].as_str().unwrap(),
            "__eunomia_dummy_user_setting"
        );
        assert_eq!(
            variables[1]["name"].as_str().unwrap(),
            "__eunomia_dummy_selected_event_ptr_user"
        );
        assert_eq!(stripped["maps"].as_array().unwrap().len(), 2);
    }
}
