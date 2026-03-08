//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    env,
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{config::Options, handle_std_command_with_log, helper::get_eunomia_data_dir};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};

const STANDALONE_RUNTIME_ENV: &str = "EUNOMIA_STANDALONE_LIB";
const EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";
const CHECKOUT_RUNTIME_TARGET_DIR: &str = "bpf-loader-rs/target/eunomia-standalone-runtime";
const BIN_DIR_NAME: &str = "bin";
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

enum RuntimeSelection {
    ExistingLibrary(PathBuf),
    CheckoutRoots(Vec<PathBuf>),
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
    flags
        .into_iter()
        .filter(|flag| !flag.is_empty() && flag != "-lgcc_s")
        .collect()
}

fn merge_native_link_args(base: Vec<String>, extra: Vec<String>) -> Vec<String> {
    let mut merged = base;
    merged.extend(extra);
    merged
}

fn pkg_config_static_link_args() -> Result<Option<Vec<String>>> {
    let output = match Command::new("pkg-config")
        .arg("--static")
        .arg("--libs")
        .args(["libelf", "zlib"])
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| anyhow!("Failed to invoke pkg-config for standalone runtime"))
        }
    };
    if !output.status.success() {
        debug!(
            "pkg-config --static --libs libelf zlib failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(None);
    }

    let link_args = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|flag| flag.trim().to_string())
        .collect::<Vec<_>>();
    Ok(Some(normalize_native_link_args(link_args)))
}

fn finalize_native_link_args(flags: Vec<String>) -> Result<Vec<String>> {
    let mut finalized = normalize_native_link_args(flags);
    if let Some(pkg_config_args) = pkg_config_static_link_args()? {
        finalized = merge_native_link_args(finalized, pkg_config_args);
    }
    if finalized.is_empty() {
        bail!("No standalone runtime link flags were resolved");
    }
    Ok(finalized)
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
    Ok(Some(finalize_native_link_args(flags)?))
}

fn default_native_link_args() -> Result<Vec<String>> {
    finalize_native_link_args(
        DEFAULT_NATIVE_LINK_ARGS
            .iter()
            .map(|flag| flag.to_string())
            .collect(),
    )
}

fn standalone_runtime_from_library_path(library_path: PathBuf) -> Result<StandaloneRuntime> {
    let native_link_args = match read_link_flags_file(&library_path)? {
        Some(link_args) => link_args,
        None => default_native_link_args()?,
    };
    Ok(StandaloneRuntime {
        library_path,
        native_link_args,
    })
}

fn first_existing_runtime_candidate<I>(candidates: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    candidates.into_iter().find(|path| path.exists())
}

fn select_runtime_resolution(
    explicit_path: Option<PathBuf>,
    eunomia_home_candidates: Option<Vec<PathBuf>>,
    installed_candidates: Vec<PathBuf>,
    checkout_roots: Vec<PathBuf>,
) -> Result<RuntimeSelection> {
    if let Some(explicit_path) = explicit_path {
        if !explicit_path.exists() {
            bail!(
                "`{}` points to `{}`, but that file does not exist",
                STANDALONE_RUNTIME_ENV,
                explicit_path.display()
            );
        }
        return Ok(RuntimeSelection::ExistingLibrary(explicit_path));
    }

    if let Some(path) =
        first_existing_runtime_candidate(eunomia_home_candidates.into_iter().flatten())
    {
        return Ok(RuntimeSelection::ExistingLibrary(path));
    }

    if let Some(path) = first_existing_runtime_candidate(installed_candidates) {
        return Ok(RuntimeSelection::ExistingLibrary(path));
    }

    if !checkout_roots.is_empty() {
        return Ok(RuntimeSelection::CheckoutRoots(checkout_roots));
    }

    bail!(
        "Failed to locate `libeunomia.a` for `--standalone`. Install `ecc` via `make -C compiler install`, or build the runtime with `cargo rustc --manifest-path bpf-loader-rs/Cargo.toml -p bpf-loader-c-wrapper --release -- --print=native-static-libs`."
    );
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

fn add_current_exe_runtime_candidates(
    primary_candidates: &mut Vec<PathBuf>,
    fallback_candidates: &mut Vec<PathBuf>,
    current_exe: &Path,
) {
    let Some(current_exe_dir) = current_exe.parent() else {
        return;
    };

    if current_exe_dir.file_name() == Some(OsStr::new(BIN_DIR_NAME)) {
        if let Some(install_root) = current_exe_dir.parent() {
            add_install_layout_candidates(primary_candidates, install_root);
        }
        add_install_layout_candidates(fallback_candidates, current_exe_dir);
        return;
    }

    add_install_layout_candidates(primary_candidates, current_exe_dir);
}

fn installed_runtime_candidates_for(
    current_exe: Option<&Path>,
    eunomia_home: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut fallback_candidates = Vec::new();

    if let Some(current_exe) = current_exe {
        add_current_exe_runtime_candidates(&mut candidates, &mut fallback_candidates, current_exe);
    }

    if let Some(eunomia_home) = eunomia_home {
        add_install_layout_candidates(&mut candidates, eunomia_home);
    }

    candidates.extend(fallback_candidates);

    candidates
}

fn installed_runtime_candidates() -> Vec<PathBuf> {
    let current_exe = env::current_exe().ok();
    let eunomia_home = get_eunomia_data_dir().ok();
    let candidates =
        installed_runtime_candidates_for(current_exe.as_deref(), eunomia_home.as_deref());

    debug!(
        "Installed standalone runtime search paths: {:?}",
        candidates
    );

    candidates
}

fn eunomia_home_runtime_candidates() -> Option<Vec<PathBuf>> {
    let eunomia_home = env::var_os(EUNOMIA_HOME_ENV)?;
    let mut candidates = Vec::new();
    add_install_layout_candidates(&mut candidates, Path::new(&eunomia_home));
    debug!(
        "EUNOMIA_HOME standalone runtime search paths: {:?}",
        candidates
    );
    Some(candidates)
}

fn checkout_runtime_build_dir(checkout_root: &Path) -> PathBuf {
    checkout_root.join(CHECKOUT_RUNTIME_TARGET_DIR)
}

fn build_runtime_from_checkout(checkout_root: &Path) -> Result<StandaloneRuntime> {
    let manifest_path = checkout_root.join("bpf-loader-rs/Cargo.toml");
    let target_dir = checkout_runtime_build_dir(checkout_root);
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
        .arg("--target-dir")
        .arg(&target_dir)
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
        finalize_native_link_args(parse_native_link_args(&combined_output).unwrap_or_default())?;

    let library_path = target_dir.join("release/libeunomia.a");
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
    match select_runtime_resolution(
        env::var(STANDALONE_RUNTIME_ENV).ok().map(PathBuf::from),
        eunomia_home_runtime_candidates(),
        installed_runtime_candidates(),
        checkout_roots(),
    )? {
        RuntimeSelection::ExistingLibrary(path) => standalone_runtime_from_library_path(path),
        RuntimeSelection::CheckoutRoots(checkout_roots) => {
            let mut build_error = None;
            for checkout_root in checkout_roots {
                match build_runtime_from_checkout(&checkout_root) {
                    Ok(runtime) => return Ok(runtime),
                    Err(err) => {
                        debug!(
                            "Failed to build checkout standalone runtime from {}: {}",
                            checkout_root.display(),
                            err
                        );
                        build_error = Some(err);
                    }
                }
            }

            if let Some(err) = build_error {
                return Err(err);
            }

            unreachable!("runtime selection should only return checkout roots when present");
        }
    }
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
        checkout_runtime_build_dir, find_checkout_root, installed_runtime_candidates_for,
        link_flags_path_for, merge_native_link_args, normalize_native_link_args,
        parse_native_link_args, resolve_standalone_runtime, select_runtime_resolution,
        RuntimeSelection, EUNOMIA_HOME_ENV, STANDALONE_RUNTIME_ENV,
    };
    use std::{
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };
    use tempfile::TempDir;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                saved: keys
                    .iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    struct CwdGuard {
        saved: PathBuf,
    }

    impl CwdGuard {
        fn capture() -> Self {
            Self {
                saved: std::env::current_dir().unwrap(),
            }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.saved).unwrap();
        }
    }

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
    fn test_normalize_native_link_args_filters_gcc_s() {
        assert_eq!(
            normalize_native_link_args(vec![
                "-lelf".to_string(),
                "-lgcc_s".to_string(),
                "-lz".to_string(),
                "-lelf".to_string(),
            ]),
            vec!["-lelf", "-lz", "-lelf"]
        );
    }

    #[test]
    fn test_merge_native_link_args_appends_missing_flags() {
        assert_eq!(
            merge_native_link_args(
                vec!["-lelf".to_string(), "-lz".to_string()],
                vec![
                    "-lz".to_string(),
                    "-lzstd".to_string(),
                    "-llzma".to_string()
                ],
            ),
            vec!["-lelf", "-lz", "-lz", "-lzstd", "-llzma"]
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
    fn test_checkout_runtime_build_dir() {
        let temp_dir = TempDir::new().unwrap();
        let repo_root = temp_dir.path();
        assert_eq!(
            checkout_runtime_build_dir(repo_root),
            repo_root.join("bpf-loader-rs/target/eunomia-standalone-runtime")
        );
    }

    #[test]
    fn test_link_flags_path_for() {
        let path = link_flags_path_for(Path::new("/tmp/libeunomia.a"));
        assert_eq!(path, Path::new("/tmp/libeunomia.a.linkflags"));
    }

    #[test]
    fn test_select_runtime_resolution_prefers_installed_runtime_over_checkout_fallbacks() {
        let temp_dir = TempDir::new().unwrap();
        let installed_runtime = temp_dir.path().join("installed/libeunomia.a");
        let checkout_root = temp_dir.path().join("repo-root");

        fs::create_dir_all(installed_runtime.parent().unwrap()).unwrap();
        fs::write(&installed_runtime, "").unwrap();
        fs::create_dir_all(&checkout_root).unwrap();

        let selection = select_runtime_resolution(
            None,
            None,
            vec![installed_runtime.clone()],
            vec![checkout_root],
        )
        .unwrap();

        match selection {
            RuntimeSelection::ExistingLibrary(path) => assert_eq!(path, installed_runtime),
            RuntimeSelection::CheckoutRoots(_) => {
                panic!("installed runtime should win before checkout fallback")
            }
        }
    }

    #[test]
    fn test_installed_runtime_candidates_prefer_supported_install_layouts_before_bin_fallbacks() {
        let candidates = installed_runtime_candidates_for(
            Some(Path::new("/opt/eunomia/bin/ecc-rs")),
            Some(Path::new("/home/test/.local/share/eunomia")),
        );

        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/opt/eunomia/libeunomia.a"),
                PathBuf::from("/opt/eunomia/lib/libeunomia.a"),
                PathBuf::from("/home/test/.local/share/eunomia/libeunomia.a"),
                PathBuf::from("/home/test/.local/share/eunomia/lib/libeunomia.a"),
                PathBuf::from("/opt/eunomia/bin/libeunomia.a"),
                PathBuf::from("/opt/eunomia/bin/lib/libeunomia.a"),
            ]
        );
    }

    #[test]
    fn test_select_runtime_resolution_prefers_supported_install_layouts_over_bin_fallbacks() {
        let temp_dir = TempDir::new().unwrap();
        let install_root = temp_dir.path().join("install-root");
        let supported_runtime = install_root.join("libeunomia.a");
        let bin_fallback = install_root.join("bin/libeunomia.a");

        fs::create_dir_all(bin_fallback.parent().unwrap()).unwrap();
        fs::write(&supported_runtime, "").unwrap();
        fs::write(&bin_fallback, "").unwrap();

        let selection = select_runtime_resolution(
            None,
            None,
            installed_runtime_candidates_for(Some(&install_root.join("bin/ecc-rs")), None),
            Vec::new(),
        )
        .unwrap();

        match selection {
            RuntimeSelection::ExistingLibrary(path) => assert_eq!(path, supported_runtime),
            RuntimeSelection::CheckoutRoots(_) => {
                panic!("supported install layout should win before bin-adjacent fallback")
            }
        }
    }

    #[test]
    fn test_installed_runtime_candidates_do_not_walk_past_non_bin_executable_dirs() {
        let candidates = installed_runtime_candidates_for(
            Some(Path::new("/tmp/build/target/release/ecc-rs")),
            None,
        );

        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/tmp/build/target/release/libeunomia.a"),
                PathBuf::from("/tmp/build/target/release/lib/libeunomia.a"),
            ]
        );
    }

    #[test]
    fn test_resolve_standalone_runtime_prefers_eunomia_home_over_checkout_builds() {
        let _lock = env_lock().lock().unwrap();
        let _env = EnvGuard::capture(&[
            EUNOMIA_HOME_ENV,
            STANDALONE_RUNTIME_ENV,
            "XDG_DATA_HOME",
            "HOME",
        ]);
        let _cwd = CwdGuard::capture();
        let temp_dir = TempDir::new().unwrap();
        let eunomia_home = temp_dir.path().join("custom-eunomia-home");
        let library_path = eunomia_home.join("libeunomia.a");
        let repo_root = temp_dir.path().join("repo-root");
        let checkout_dir = repo_root.join("compiler/cmd/src");

        fs::create_dir_all(&eunomia_home).unwrap();
        fs::write(&library_path, "").unwrap();
        fs::write(link_flags_path_for(&library_path), "-lelf").unwrap();

        fs::create_dir_all(repo_root.join("bpf-loader-rs")).unwrap();
        fs::create_dir_all(&checkout_dir).unwrap();
        fs::write(repo_root.join("bpf-loader-rs/Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(
            repo_root.join("compiler/cmd/Cargo.toml"),
            "[package]\nname = \"dummy\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();

        std::env::set_var(EUNOMIA_HOME_ENV, &eunomia_home);
        std::env::remove_var(STANDALONE_RUNTIME_ENV);
        std::env::remove_var("XDG_DATA_HOME");
        std::env::remove_var("HOME");
        std::env::set_current_dir(&checkout_dir).unwrap();

        let runtime = resolve_standalone_runtime().unwrap();
        assert_eq!(runtime.library_path, library_path);
    }
}
