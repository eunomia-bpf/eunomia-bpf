//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{config::Options, handle_std_command_with_log, helper::get_eunomia_data_dir};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};

const STANDALONE_RUNTIME_ENV: &str = "EUNOMIA_STANDALONE_LIB";
const DEFAULT_NATIVE_LINK_ARGS: &[&str] = &[
    "-lelf",
    "-lz",
    "-lutil",
    "-lrt",
    "-lpthread",
    "-lm",
    "-ldl",
    "-lc",
];

struct StandaloneRuntime {
    library_path: PathBuf,
    native_link_args: Vec<String>,
}

fn num_to_hex(v: u8) -> char {
    match v {
        0..=9 => (48 + v) as char,
        10..=15 => (v - 10 + 97) as char,
        _ => panic!(),
    }
}

fn push_candidate(candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !candidates.iter().any(|existing| existing == &candidate) {
        candidates.push(candidate);
    }
}

fn add_install_layout_candidates(candidates: &mut Vec<PathBuf>, root: &Path) {
    push_candidate(candidates, root.join("libeunomia.a"));
    push_candidate(candidates, root.join("lib/libeunomia.a"));
}

fn link_flags_path_for(library_path: &Path) -> PathBuf {
    let file_name = library_path
        .file_name()
        .expect("library path should have a file name")
        .to_string_lossy();
    library_path.with_file_name(format!("{file_name}.linkflags"))
}

fn parse_native_link_args(raw: &str) -> Option<Vec<String>> {
    raw.lines()
        .find_map(|line| line.split_once("native-static-libs: "))
        .map(|(_, flags)| {
            flags
                .split_whitespace()
                .map(|flag| flag.trim().to_string())
                .collect::<Vec<_>>()
        })
        .map(normalize_native_link_args)
        .filter(|flags| !flags.is_empty())
}

fn normalize_native_link_args(flags: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for flag in flags {
        if flag.is_empty() || flag == "-lgcc_s" {
            continue;
        }
        if !normalized.iter().any(|existing| existing == &flag) {
            normalized.push(flag);
        }
    }
    normalized
}

fn read_link_flags_file(library_path: &Path) -> Result<Option<Vec<String>>> {
    let link_flags_path = link_flags_path_for(library_path);
    if !link_flags_path.exists() {
        return Ok(None);
    }
    let flags = fs::read_to_string(&link_flags_path).with_context(|| {
        anyhow!(
            "Failed to read standalone runtime link flags from {:?}",
            link_flags_path
        )
    })?;
    let flags = flags
        .split_whitespace()
        .map(|flag| flag.trim().to_string())
        .collect::<Vec<_>>();
    let flags = normalize_native_link_args(flags);
    if flags.is_empty() {
        bail!(
            "Standalone runtime link flags file {:?} is empty",
            link_flags_path
        );
    }
    Ok(Some(flags))
}

fn default_native_link_args() -> Vec<String> {
    DEFAULT_NATIVE_LINK_ARGS
        .iter()
        .map(|flag| flag.to_string())
        .collect()
}

fn standalone_runtime_from_library_path(library_path: PathBuf) -> Result<StandaloneRuntime> {
    let native_link_args =
        read_link_flags_file(&library_path)?.unwrap_or_else(default_native_link_args);
    Ok(StandaloneRuntime {
        library_path,
        native_link_args,
    })
}

fn find_checkout_root(start: &Path) -> Option<PathBuf> {
    for candidate in start.ancestors() {
        if candidate.join("bpf-loader-rs/Cargo.toml").is_file()
            && candidate.join("compiler/cmd/Cargo.toml").is_file()
        {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

fn checkout_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for start in [
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        env::current_dir().ok(),
        env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf)),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(root) = find_checkout_root(&start) {
            push_candidate(&mut roots, root);
        }
    }
    roots
}

fn add_checkout_runtime_candidates(candidates: &mut Vec<PathBuf>, checkout_root: &Path) {
    let target_dir = checkout_root.join("bpf-loader-rs/target");
    push_candidate(candidates, target_dir.join("release/libeunomia.a"));
    push_candidate(candidates, target_dir.join("debug/libeunomia.a"));

    if let Ok(entries) = fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                push_candidate(candidates, path.join("release/libeunomia.a"));
                push_candidate(candidates, path.join("debug/libeunomia.a"));
            }
        }
    }
}

fn bundled_runtime_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(current_exe) = env::current_exe() {
        if let Some(current_exe_dir) = current_exe.parent() {
            for ancestor in current_exe_dir.ancestors() {
                add_install_layout_candidates(&mut candidates, ancestor);
            }
        }
    }

    if let Ok(eunomia_home) = get_eunomia_data_dir() {
        add_install_layout_candidates(&mut candidates, &eunomia_home);
    }

    for checkout_root in checkout_roots() {
        add_checkout_runtime_candidates(&mut candidates, &checkout_root);
    }

    debug!("Standalone runtime search paths: {:?}", candidates);

    candidates
}

fn build_runtime_from_checkout(checkout_root: &Path) -> Result<StandaloneRuntime> {
    let manifest_path = checkout_root.join("bpf-loader-rs/Cargo.toml");
    info!(
        "Building standalone runtime from {}",
        manifest_path.display()
    );

    let output = Command::new("cargo")
        .arg("rustc")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("-p")
        .arg("bpf-loader-c-wrapper")
        .arg("--release")
        .arg("--")
        .arg("--print=native-static-libs")
        .output()
        .with_context(|| anyhow!("Failed to invoke cargo to build standalone runtime"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        log::info!("$ cargo rustc --manifest-path {:?} -p bpf-loader-c-wrapper --release -- --print=native-static-libs", manifest_path);
        log::info!("{stdout}");
        log::error!("{stderr}");
        bail!(
            "Failed to build standalone runtime (exit code = {:?})",
            output.status.code()
        );
    }

    let combined_output = format!("{stdout}\n{stderr}");
    let native_link_args =
        parse_native_link_args(&combined_output).unwrap_or_else(default_native_link_args);

    let library_path = checkout_root.join("bpf-loader-rs/target/release/libeunomia.a");
    if !library_path.exists() {
        bail!(
            "Built standalone runtime but `{}` was not produced",
            library_path.display()
        );
    }

    let link_flags_path = link_flags_path_for(&library_path);
    fs::write(&link_flags_path, native_link_args.join(" ")).with_context(|| {
        anyhow!(
            "Failed to write standalone runtime link flags to {}",
            link_flags_path.display()
        )
    })?;

    Ok(StandaloneRuntime {
        library_path,
        native_link_args,
    })
}

fn resolve_standalone_runtime() -> Result<StandaloneRuntime> {
    if let Ok(explicit_path) = env::var(STANDALONE_RUNTIME_ENV) {
        let explicit_path = PathBuf::from(explicit_path);
        if !explicit_path.exists() {
            bail!(
                "`{}` points to `{}`, but that file does not exist",
                STANDALONE_RUNTIME_ENV,
                explicit_path.display()
            );
        }
        return standalone_runtime_from_library_path(explicit_path);
    }

    let candidates = bundled_runtime_candidates();
    if let Some(path) = candidates.into_iter().find(|path| path.exists()) {
        return standalone_runtime_from_library_path(path);
    }

    let mut build_error = None;
    for checkout_root in checkout_roots() {
        match build_runtime_from_checkout(&checkout_root) {
            Ok(runtime) => return Ok(runtime),
            Err(err) => build_error = Some(err),
        }
    }
    if let Some(err) = build_error {
        return Err(err);
    }

    bail!(
        "Failed to locate `libeunomia.a` for `--standalone`. Install `ecc` via `make -C compiler install`, or build the runtime with `cargo rustc --manifest-path bpf-loader-rs/Cargo.toml -p bpf-loader-c-wrapper --release -- --print=native-static-libs`."
    );
}

pub(crate) fn build_standalone_executable(opts: &Options) -> Result<()> {
    info!("Generating standalone executable..");
    let template_source = include_str!("standalone_bpf_loader.template.c");
    let runtime = resolve_standalone_runtime()?;
    let package_json_content = std::fs::read_to_string(opts.get_output_package_config_path())
        .with_context(|| anyhow!("Failed to read package json"))?;
    let bytes_str = package_json_content
        .as_bytes()
        .iter()
        .map(|x| {
            // For simplicity, we manually handle the conversion
            let a = x / 16;
            let b = x % 16;
            format!("\\x{}{}", num_to_hex(a), num_to_hex(b))
        })
        .collect::<Vec<_>>()
        .join("");
    let source = template_source.replace("<REPLACE-HERE>", &bytes_str);
    let source_path = opts.get_standalone_source_file_path();
    std::fs::write(&source_path, source).with_context(|| {
        anyhow!(
            "Failed to write out the source of standalone executable to {:?}",
            source_path
        )
    })?;
    let executable_path = opts.get_standalone_executable_path();
    let mut cmd = Command::new(&opts.compile_opts.parameters.clang_bin);
    cmd.arg("-Wall")
        .arg("-O2")
        .arg("-static")
        .arg(source_path)
        .arg(&runtime.library_path)
        .args(&runtime.native_link_args)
        .arg("-o")
        .arg(&executable_path);
    handle_std_command_with_log!(cmd, "Failed to build the standalone executable");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        add_checkout_runtime_candidates, find_checkout_root, link_flags_path_for,
        parse_native_link_args,
    };
    use std::{fs, path::Path};
    use tempfile::TempDir;

    #[test]
    fn test_parse_native_link_args() {
        let parsed =
            parse_native_link_args("note: native-static-libs: -lelf -lz -lpthread -lm -ldl -lc")
                .unwrap();
        assert_eq!(
            parsed,
            vec!["-lelf", "-lz", "-lpthread", "-lm", "-ldl", "-lc"]
        );
    }

    #[test]
    fn test_find_checkout_root() {
        let temp_dir = TempDir::new().unwrap();
        let repo_root = temp_dir.path();
        fs::create_dir_all(repo_root.join("bpf-loader-rs")).unwrap();
        fs::create_dir_all(repo_root.join("compiler/cmd/src")).unwrap();
        fs::write(repo_root.join("bpf-loader-rs/Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(repo_root.join("compiler/cmd/Cargo.toml"), "[package]\n").unwrap();

        let nested = repo_root.join("compiler/cmd/src");
        assert_eq!(find_checkout_root(&nested).as_deref(), Some(repo_root));
    }

    #[test]
    fn test_add_checkout_runtime_candidates() {
        let temp_dir = TempDir::new().unwrap();
        let repo_root = temp_dir.path();
        let target_dir = repo_root.join("bpf-loader-rs/target/x86_64-unknown-linux-gnu");
        fs::create_dir_all(target_dir.join("release")).unwrap();

        let mut candidates = Vec::new();
        add_checkout_runtime_candidates(&mut candidates, repo_root);

        assert!(candidates.iter().any(|candidate| {
            candidate == &repo_root.join("bpf-loader-rs/target/release/libeunomia.a")
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate
                == &repo_root
                    .join("bpf-loader-rs/target/x86_64-unknown-linux-gnu/release/libeunomia.a")
        }));
    }

    #[test]
    fn test_link_flags_path_for() {
        let path = link_flags_path_for(Path::new("/tmp/libeunomia.a"));
        assert_eq!(path, Path::new("/tmp/libeunomia.a.linkflags"));
    }
}
