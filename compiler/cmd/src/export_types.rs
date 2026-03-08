//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{fs, path::Path};

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

fn entity_is_in_file(entity: &Entity, expected_path: &Path) -> bool {
    entity
        .get_location()
        .and_then(|location| location.get_file_location().file)
        .map(|file| file.get_path() == expected_path)
        .unwrap_or(false)
}

fn has_export_annotation(entity: &Entity) -> bool {
    entity
        .get_comment()
        .map(|comment| comment.contains(EXPORT_ANNOTATION))
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

fn collect_export_struct_candidates(args: &Options) -> Result<Vec<ExportStructCandidate>> {
    let source_path = Path::new(&args.compile_opts.source_path)
        .canonicalize()
        .with_context(|| anyhow!("Failed to canonicalize source path"))?;
    let export_header_path = Path::new(&args.compile_opts.export_event_header)
        .canonicalize()
        .with_context(|| anyhow!("Failed to canonicalize export header path"))?;

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
        content += &format!(
            "const volatile struct {} * __eunomia_dummy_{}_ptr  __attribute__((unused));\n",
            struct_name, struct_name
        );
    }
    fs::write(file_path, content)?;
    Ok(())
}

pub fn strip_synthetic_bpf_skel_symbols(mut bpf_skel: Value) -> Value {
    let mut removed_section_idents = Vec::new();
    if let Some(data_sections) = bpf_skel["data_sections"].as_array_mut() {
        for data_section in data_sections.iter_mut() {
            if let Some(variables) = data_section["variables"].as_array_mut() {
                variables.retain(|variable| {
                    variable["name"]
                        .as_str()
                        .map(|name| !name.starts_with(DUMMY_PTR_PREFIX))
                        .unwrap_or(true)
                });
            }
            let should_remove = data_section["variables"]
                .as_array()
                .map(|variables| variables.is_empty())
                .unwrap_or(false);
            if should_remove {
                if let Some(ident) = data_section["name"]
                    .as_str()
                    .and_then(|name| name.strip_prefix('.'))
                {
                    removed_section_idents.push(ident.to_string());
                }
            }
        }
        data_sections.retain(|data_section| {
            !data_section["variables"]
                .as_array()
                .map(|variables| variables.is_empty())
                .unwrap_or(false)
        });
    }
    if let Some(maps) = bpf_skel["maps"].as_array_mut() {
        maps.retain(|map| {
            let mmaped = map["mmaped"].as_bool().unwrap_or(false);
            let ident = map["ident"].as_str().unwrap_or_default();
            !(mmaped
                && removed_section_idents
                    .iter()
                    .any(|removed| removed == ident))
        });
    }
    bpf_skel
}

#[cfg(test)]
mod test {
    use std::{fs, path::Path};

    use clap::Parser;
    use tempfile::TempDir;

    use super::{add_unused_ptr_for_structs, find_all_export_structs};
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
}
