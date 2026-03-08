//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::bpf_compiler::standalone::{build_standalone_executable, render_standalone_source};
use crate::config::{
    fetch_btfhub_repo, generate_tailored_btf, get_bpf_compile_args, get_bpftool_path,
    options::current_unix_time_nanos, package_btfhub_tar, Options,
};
use crate::document_parser::parse_source_documents;
use crate::export_types::{add_unused_ptr_for_structs, find_all_export_structs};
use crate::handle_std_command_with_log;
use crate::wasm::render_wasm_header;
use anyhow::{anyhow, bail, Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::{fs, path::Path};
use tempfile::{Builder, NamedTempFile, TempDir};
use walkdir::WalkDir;

#[cfg(test)]
use std::sync::{Arc, Barrier, Mutex, OnceLock};

pub(crate) mod standalone;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct OutputArtifactOwner {
    object_name: String,
    source_path: String,
    #[serde(default)]
    source_snapshot: OutputArtifactSourceSnapshot,
    #[serde(default)]
    build_signature: OutputArtifactBuildSignature,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
struct OutputArtifactSourceSnapshot {
    #[serde(default)]
    digest: String,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
struct OutputArtifactBuildSignature {
    header_only: bool,
    export_event_header: Option<String>,
    wasm_header: bool,
    btfgen: bool,
    btfhub_archive: Option<String>,
    generate_package: bool,
    standalone: bool,
    additional_cflags: Vec<String>,
    workspace_path: Option<String>,
    clang_bin: String,
    llvm_strip_bin: String,
}

impl OutputArtifactOwner {
    fn matches_revision(&self, other: &Self) -> bool {
        self.object_name == other.object_name
            && self.source_path == other.source_path
            && self.source_snapshot.matches(&other.source_snapshot)
            && self
                .build_signature
                .matches_package_lineage(&other.build_signature)
    }

    fn matches_package_lineage(&self, other: &Self) -> bool {
        self.matches_revision(other)
    }

    fn is_legacy_upgrade_target_for(&self, other: &Self) -> bool {
        self.source_snapshot.is_missing()
            && self.object_name == other.object_name
            && self.source_path == other.source_path
            && self
                .build_signature
                .matches_package_lineage(&other.build_signature)
    }
}

impl OutputArtifactSourceSnapshot {
    fn matches(&self, other: &Self) -> bool {
        self.digest == other.digest
    }

    fn is_missing(&self) -> bool {
        self.digest.is_empty()
    }
}

impl OutputArtifactBuildSignature {
    fn matches_package_lineage(&self, other: &Self) -> bool {
        self.header_only == other.header_only
            && self.export_event_header == other.export_event_header
            && self.wasm_header == other.wasm_header
            && self.btfgen == other.btfgen
            && self.btfhub_archive == other.btfhub_archive
            && self.generate_package == other.generate_package
            && self.standalone == other.standalone
            && self.additional_cflags == other.additional_cflags
            && self.workspace_path == other.workspace_path
            && self.clang_bin == other.clang_bin
            && self.llvm_strip_bin == other.llvm_strip_bin
    }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct OutputArtifactMarker {
    owner: OutputArtifactOwner,
    #[serde(default)]
    finalized_at_unix_nanos: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct OutputArtifactClaim {
    owner: OutputArtifactOwner,
    invocation_id: String,
    #[serde(default)]
    started_at_unix_nanos: u64,
}

#[derive(Debug, Clone)]
struct OutputArtifactInvocation {
    started_at_unix_nanos: u64,
    claim: OutputArtifactClaim,
}

impl OutputArtifactInvocation {
    fn start(args: &Options) -> Result<Self> {
        let owner = build_output_artifact_owner(args)?;
        let invocation_id = build_output_artifact_invocation_id(args);
        let started_at_unix_nanos =
            find_existing_output_artifact_invocation_started_at(args, &invocation_id, &owner)?
                .unwrap_or_else(current_unix_time_nanos);
        Ok(Self {
            started_at_unix_nanos,
            claim: OutputArtifactClaim {
                owner,
                invocation_id,
                started_at_unix_nanos,
            },
        })
    }

    fn owner(&self) -> &OutputArtifactOwner {
        &self.claim.owner
    }
}

#[must_use = "output artifact claims must be explicitly released to surface cleanup errors"]
struct OutputArtifactClaimsGuard {
    artifact_paths: Vec<PathBuf>,
    claim: OutputArtifactClaim,
}

impl OutputArtifactClaimsGuard {
    fn new(invocation: &OutputArtifactInvocation) -> Self {
        Self {
            artifact_paths: Vec::new(),
            claim: invocation.claim.clone(),
        }
    }

    fn track(&mut self, artifact_path: PathBuf) {
        self.artifact_paths.push(artifact_path);
    }

    fn release(mut self) -> Result<()> {
        self.release_tracked_claims()
    }

    fn release_tracked_claims(&mut self) -> Result<()> {
        let mut release_errors = Vec::new();
        while let Some(artifact_path) = self.artifact_paths.pop() {
            if let Err(err) = release_output_artifact_claim(&self.claim, &artifact_path) {
                release_errors.push(format!("{}: {err}", artifact_path.display()));
            }
        }

        if release_errors.is_empty() {
            return Ok(());
        }

        bail!(
            "Failed to release output artifact claims: {}",
            release_errors.join("; ")
        );
    }
}

impl Drop for OutputArtifactClaimsGuard {
    fn drop(&mut self) {
        if self.artifact_paths.is_empty() {
            return;
        }

        if let Err(err) = self.release_tracked_claims() {
            error!("Output artifact claims dropped without explicit release: {err}");
        } else if !std::thread::panicking() {
            error!("Output artifact claims dropped without explicit release");
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct OutputArtifactMarkerPublishBarrier {
    marker_path: PathBuf,
    barrier: Arc<Barrier>,
}

#[cfg(test)]
static OUTPUT_ARTIFACT_MARKER_PUBLISH_BARRIER: OnceLock<
    Mutex<Option<OutputArtifactMarkerPublishBarrier>>,
> = OnceLock::new();

#[cfg(test)]
#[derive(Clone)]
struct OutputArtifactClaimPublishBarrier {
    claim_path: PathBuf,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(test)]
static OUTPUT_ARTIFACT_CLAIM_PUBLISH_BARRIER: OnceLock<
    Mutex<Option<OutputArtifactClaimPublishBarrier>>,
> = OnceLock::new();

#[cfg(test)]
#[derive(Clone)]
struct OutputArtifactClaimReleaseFailure {
    claim_path: PathBuf,
    message: String,
}

#[cfg(test)]
static OUTPUT_ARTIFACT_CLAIM_RELEASE_FAILURE: OnceLock<
    Mutex<Option<OutputArtifactClaimReleaseFailure>>,
> = OnceLock::new();

#[cfg(test)]
#[derive(Clone)]
struct OutputArtifactCleanupReservationBarrier {
    reservation_path: PathBuf,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(test)]
static OUTPUT_ARTIFACT_CLEANUP_RESERVATION_BARRIER: OnceLock<
    Mutex<Option<OutputArtifactCleanupReservationBarrier>>,
> = OnceLock::new();

#[cfg(test)]
#[derive(Clone)]
struct OutputObjectPublishBarrier {
    artifact_path: PathBuf,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(test)]
static OUTPUT_OBJECT_PUBLISH_BARRIER: OnceLock<Mutex<Option<OutputObjectPublishBarrier>>> =
    OnceLock::new();

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

fn create_output_artifact_tempfile(
    output_artifact_path: impl AsRef<Path>,
) -> Result<NamedTempFile> {
    let output_artifact_path = output_artifact_path.as_ref();
    let output_dir = output_artifact_path
        .parent()
        .expect("Output artifacts are expected to have a parent directory");
    let temp_prefix = format!(
        ".tmp-output-object-{}-",
        output_artifact_path
            .file_name()
            .expect("Output artifacts are expected to have a file name")
            .to_string_lossy()
    );

    Builder::new()
        .prefix(&temp_prefix)
        .suffix(".tmp")
        .tempfile_in(output_dir)
        .map_err(Into::into)
}

fn create_output_object_tempfile(output_artifact_path: impl AsRef<Path>) -> Result<NamedTempFile> {
    create_output_artifact_tempfile(output_artifact_path)
}

fn create_output_artifact_tempdir(output_artifact_path: impl AsRef<Path>) -> Result<TempDir> {
    let output_artifact_path = output_artifact_path.as_ref();
    let output_dir = output_artifact_path
        .parent()
        .expect("Output artifacts are expected to have a parent directory");
    let temp_prefix = format!(
        ".tmp-output-dir-{}-",
        output_artifact_path
            .file_name()
            .expect("Output artifacts are expected to have a file name")
            .to_string_lossy()
    );

    Builder::new()
        .prefix(&temp_prefix)
        .tempdir_in(output_dir)
        .map_err(Into::into)
}

fn io_error_is_directory_not_empty(err: &std::io::Error) -> bool {
    #[cfg(windows)]
    const DIRECTORY_NOT_EMPTY_OS_ERROR: i32 = 145;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const DIRECTORY_NOT_EMPTY_OS_ERROR: i32 = 66;
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
    const DIRECTORY_NOT_EMPTY_OS_ERROR: i32 = 39;

    err.raw_os_error() == Some(DIRECTORY_NOT_EMPTY_OS_ERROR)
}

fn output_artifact_conflict_error(artifact_path: impl AsRef<Path>, action: &str) -> anyhow::Error {
    anyhow!(
        "Refusing to {} {} because it belongs to a different source or build",
        action,
        artifact_path.as_ref().display()
    )
}

fn output_artifact_files_match(
    expected_artifact_path: impl AsRef<Path>,
    actual_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let expected_artifact_path = expected_artifact_path.as_ref();
    let actual_artifact_path = actual_artifact_path.as_ref();
    let expected_metadata = fs::metadata(expected_artifact_path)?;
    let actual_metadata = fs::metadata(actual_artifact_path)?;
    if expected_metadata.len() != actual_metadata.len() {
        return Ok(false);
    }

    let mut expected_reader = BufReader::new(fs::File::open(expected_artifact_path)?);
    let mut actual_reader = BufReader::new(fs::File::open(actual_artifact_path)?);
    let mut expected_buffer = [0_u8; 8192];
    let mut actual_buffer = [0_u8; 8192];
    loop {
        let expected_bytes_read = expected_reader.read(&mut expected_buffer)?;
        let actual_bytes_read = actual_reader.read(&mut actual_buffer)?;
        if expected_bytes_read != actual_bytes_read {
            return Ok(false);
        }
        if expected_bytes_read == 0 {
            return Ok(true);
        }
        if expected_buffer[..expected_bytes_read] != actual_buffer[..actual_bytes_read] {
            return Ok(false);
        }
    }
}

fn collect_output_artifact_directory_entries(
    artifact_path: impl AsRef<Path>,
) -> Result<Vec<(PathBuf, bool)>> {
    let artifact_path = artifact_path.as_ref();
    let mut entries = Vec::new();
    for entry in WalkDir::new(artifact_path) {
        let entry = entry?;
        let relative_path = entry
            .path()
            .strip_prefix(artifact_path)
            .expect("walkdir entries should stay within the artifact path")
            .to_path_buf();
        entries.push((relative_path, entry.file_type().is_dir()));
    }
    entries.sort();
    Ok(entries)
}

fn output_artifact_directories_match(
    expected_artifact_path: impl AsRef<Path>,
    actual_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let expected_artifact_path = expected_artifact_path.as_ref();
    let actual_artifact_path = actual_artifact_path.as_ref();
    let expected_entries = collect_output_artifact_directory_entries(expected_artifact_path)?;
    let actual_entries = collect_output_artifact_directory_entries(actual_artifact_path)?;
    if expected_entries != actual_entries {
        return Ok(false);
    }

    for (relative_path, is_dir) in expected_entries {
        if is_dir {
            continue;
        }

        if !output_artifact_files_match(
            expected_artifact_path.join(&relative_path),
            actual_artifact_path.join(&relative_path),
        )? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn finalize_legacy_output_artifact_upgrade_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    built_artifact_path: impl AsRef<Path>,
    output_artifact_path: impl AsRef<Path>,
    action: &str,
) -> Result<bool> {
    let built_artifact_path = built_artifact_path.as_ref();
    let output_artifact_path = output_artifact_path.as_ref();
    let marker_path = args.get_output_artifact_marker_path(output_artifact_path);
    if !marker_path.exists() || !output_artifact_path.exists() {
        return Ok(false);
    }

    let marker = read_output_artifact_marker(&marker_path)?;
    if !marker
        .owner
        .is_legacy_upgrade_target_for(invocation.owner())
    {
        return Ok(false);
    }

    let artifacts_match = if built_artifact_path.is_file() && output_artifact_path.is_file() {
        output_artifact_files_match(built_artifact_path, output_artifact_path)?
    } else if built_artifact_path.is_dir() && output_artifact_path.is_dir() {
        output_artifact_directories_match(built_artifact_path, output_artifact_path)?
    } else {
        false
    };
    if !artifacts_match {
        return Err(output_artifact_conflict_error(output_artifact_path, action));
    }

    record_output_artifact_finalization_for_invocation(invocation, args, output_artifact_path)?;
    Ok(true)
}

fn publish_output_file_artifact_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    output_artifact_file: NamedTempFile,
    output_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let output_artifact_path = output_artifact_path.as_ref();
    let temp_artifact_path = output_artifact_file.path().to_path_buf();
    #[cfg(test)]
    wait_for_output_object_publish(output_artifact_path);
    match output_artifact_file.persist_noclobber(output_artifact_path) {
        Ok(_) => {
            record_output_artifact_finalization_for_invocation(
                invocation,
                args,
                output_artifact_path,
            )?;
            Ok(true)
        }
        Err(err) if err.error.kind() == ErrorKind::AlreadyExists => {
            if finalize_legacy_output_artifact_upgrade_for_invocation(
                invocation,
                args,
                &temp_artifact_path,
                output_artifact_path,
                if output_artifact_path.exists() {
                    "overwrite existing output artifact"
                } else {
                    "claim output artifact"
                },
            )? {
                return Ok(false);
            }
            ensure_output_artifact_can_be_written_for_invocation(
                invocation,
                args,
                output_artifact_path,
            )?;
            Ok(false)
        }
        Err(err) => Err(err.error.into()),
    }
}

fn publish_output_object_artifact(
    args: &Options,
    output_object_file: NamedTempFile,
    output_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let invocation = OutputArtifactInvocation::start(args)?;
    publish_output_object_artifact_for_invocation(
        &invocation,
        args,
        output_object_file,
        output_artifact_path,
    )
}

fn publish_output_object_artifact_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    output_object_file: NamedTempFile,
    output_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    publish_output_file_artifact_for_invocation(
        invocation,
        args,
        output_object_file,
        output_artifact_path,
    )
}

fn publish_output_file_artifact(
    args: &Options,
    output_artifact_file: NamedTempFile,
    output_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let invocation = OutputArtifactInvocation::start(args)?;
    publish_output_file_artifact_for_invocation(
        &invocation,
        args,
        output_artifact_file,
        output_artifact_path,
    )
}

fn publish_standalone_artifacts_for_invocation<F>(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    standalone_source: String,
    build_executable: F,
) -> Result<()>
where
    F: FnOnce(&Path, &Path) -> Result<()>,
{
    let source_path = args.get_standalone_source_file_path();
    let executable_path = args.get_standalone_executable_path();
    let mut source_file = create_output_artifact_tempfile(&source_path)?;
    source_file
        .as_file_mut()
        .write_all(standalone_source.as_bytes())?;
    source_file.as_file_mut().sync_all()?;

    let mut executable_file = create_output_artifact_tempfile(&executable_path)?;
    build_executable(source_file.path(), executable_file.path())?;
    executable_file.as_file_mut().sync_all()?;

    publish_output_file_artifact_for_invocation(invocation, args, source_file, &source_path)?;
    publish_output_file_artifact_for_invocation(
        invocation,
        args,
        executable_file,
        &executable_path,
    )?;
    Ok(())
}

fn build_standalone_artifacts_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<()> {
    let standalone_source = render_standalone_source(args)?;
    publish_standalone_artifacts_for_invocation(
        invocation,
        args,
        standalone_source,
        |source_path, executable_path| {
            build_standalone_executable(args, source_path, executable_path)
        },
    )
}

fn publish_wasm_header_artifact_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<()> {
    let output_wasm_header_path = args.get_wasm_header_path();
    let mut output_wasm_header_file = create_output_artifact_tempfile(&output_wasm_header_path)?;
    output_wasm_header_file
        .as_file_mut()
        .write_all(render_wasm_header(args)?.as_bytes())?;
    output_wasm_header_file.as_file_mut().sync_all()?;
    publish_output_file_artifact_for_invocation(
        invocation,
        args,
        output_wasm_header_file,
        &output_wasm_header_path,
    )?;
    Ok(())
}

fn publish_output_directory_artifact_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    output_artifact_dir: TempDir,
    output_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let output_artifact_path = output_artifact_path.as_ref();
    let temp_artifact_path = output_artifact_dir.into_path();
    match fs::rename(&temp_artifact_path, output_artifact_path) {
        Ok(_) => {
            record_output_artifact_finalization_for_invocation(
                invocation,
                args,
                output_artifact_path,
            )?;
            Ok(true)
        }
        Err(err)
            if err.kind() == ErrorKind::AlreadyExists || io_error_is_directory_not_empty(&err) =>
        {
            let legacy_upgrade_result = finalize_legacy_output_artifact_upgrade_for_invocation(
                invocation,
                args,
                &temp_artifact_path,
                output_artifact_path,
                if output_artifact_path.exists() {
                    "overwrite existing output artifact"
                } else {
                    "claim output artifact"
                },
            );
            let cleanup_result = match fs::remove_dir_all(&temp_artifact_path) {
                Ok(_) => Ok(()),
                Err(cleanup_err) if cleanup_err.kind() == ErrorKind::NotFound => Ok(()),
                Err(cleanup_err) => Err(cleanup_err),
            };
            if let Ok(true) = legacy_upgrade_result {
                cleanup_result?;
                return Ok(false);
            }
            legacy_upgrade_result?;
            ensure_output_artifact_can_be_written_for_invocation(
                invocation,
                args,
                output_artifact_path,
            )?;
            cleanup_result?;
            Ok(false)
        }
        Err(err) => {
            match fs::remove_dir_all(&temp_artifact_path) {
                Ok(_) => {}
                Err(cleanup_err) if cleanup_err.kind() == ErrorKind::NotFound => {}
                Err(cleanup_err) => {
                    return Err(anyhow!(
                        "Failed to rename output directory {} into place: {err}. Failed to clean up temporary output directory {}: {cleanup_err}",
                        output_artifact_path.display(),
                        temp_artifact_path.display()
                    ));
                }
            }
            Err(err.into())
        }
    }
}

fn publish_output_directory_artifact(
    args: &Options,
    output_artifact_dir: TempDir,
    output_artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let invocation = OutputArtifactInvocation::start(args)?;
    publish_output_directory_artifact_for_invocation(
        &invocation,
        args,
        output_artifact_dir,
        output_artifact_path,
    )
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
fn do_compile(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    temp_source_file: impl AsRef<Path>,
) -> Result<()> {
    let output_bpf_object_path = args.get_output_object_path();
    let output_json_path = args.get_output_config_path();
    // Build the shared object via an invocation-local temp file so overlapping
    // same-source builds never write the final `.bpf.o` in place.
    let output_bpf_object_file = create_output_object_tempfile(&output_bpf_object_path)?;
    let output_bpf_object_temp_path = output_bpf_object_file.path().to_path_buf();
    let mut meta_json = json!({});

    // compile bpf object
    info!("Compiling bpf object...");
    claim_output_artifact_for_invocation(invocation, args, &output_bpf_object_path)?;
    compile_bpf_object(args, temp_source_file, &output_bpf_object_temp_path)?;
    let bpf_skel_json = get_bpf_skel_json(&output_bpf_object_temp_path, args)?;
    let bpf_skel = serde_json::from_str::<Value>(&bpf_skel_json)
        .with_context(|| anyhow!("Failed to parse json skeleton"))?;
    let bpf_skel_with_doc = parse_source_documents(args, &args.compile_opts.source_path, bpf_skel)
        .with_context(|| anyhow!("Failed to parse source documents"))?;
    meta_json["bpf_skel"] = bpf_skel_with_doc;

    // compile export types
    if !args.compile_opts.export_event_header.is_empty() {
        info!("Generating export types...");
        let export_types_json = get_export_types_json(args, &output_bpf_object_temp_path)?;
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
    claim_output_artifact_for_invocation(invocation, args, &output_json_path)?;
    let mut output_json_file = create_output_artifact_tempfile(&output_json_path)?;
    output_json_file
        .as_file_mut()
        .write_all(meta_config_str.as_bytes())?;
    output_json_file.as_file_mut().sync_all()?;
    publish_output_file_artifact_for_invocation(
        invocation,
        args,
        output_json_file,
        &output_json_path,
    )?;
    publish_output_object_artifact_for_invocation(
        invocation,
        args,
        output_bpf_object_file,
        &output_bpf_object_path,
    )?;
    Ok(())
}

/// compile JSON file
pub fn compile_bpf(args: &Options) -> Result<()> {
    debug!("Compiling..");
    let invocation = OutputArtifactInvocation::start(args)?;
    // backup old files
    let source_file_content = fs::read_to_string(&args.compile_opts.source_path)?;
    let mut temp_source_file = PathBuf::from(&args.compile_opts.source_path);

    let claimed_output_artifacts =
        claim_requested_output_artifacts_for_invocation(&invocation, args)?;
    let compile_result = (|| -> Result<()> {
        if !args.compile_opts.export_event_header.is_empty() {
            temp_source_file = args.get_source_file_temp_path();
            // create temp source file
            fs::write(&temp_source_file, source_file_content)?;
            add_unused_ptr_for_structs(&args.compile_opts, &temp_source_file)?;
        }
        do_compile(&invocation, args, &temp_source_file)
            .with_context(|| anyhow!("Failed to compile"))?;
        if !args.compile_opts.export_event_header.is_empty() {
            fs::remove_file(temp_source_file)?;
        }
        if !args.compile_opts.parameters.no_generate_package_json {
            pack_object_in_config_for_invocation(&invocation, args)
                .with_context(|| anyhow!("Failed to generate package artifact"))?;
        }
        // If we want a standalone executable..?
        if args.compile_opts.parameters.standalone {
            build_standalone_artifacts_for_invocation(&invocation, args)
                .with_context(|| anyhow!("Failed to build standalone executable"))?;
        }
        if args.compile_opts.wasm_header {
            publish_wasm_header_artifact_for_invocation(&invocation, args)
                .with_context(|| anyhow!("Failed to generate wasm header"))?;
        }
        if args.compile_opts.btfgen {
            let output_btf_archive_path = args.get_output_btf_archive_directory();
            let output_btf_archive_dir = create_output_artifact_tempdir(&output_btf_archive_path)?;
            fetch_btfhub_repo(&args.compile_opts)
                .with_context(|| anyhow!("Failed to fetch btfhub repo"))?;
            generate_tailored_btf(args, output_btf_archive_dir.path())
                .with_context(|| anyhow!("Failed to generate tailored btf"))?;
            publish_output_directory_artifact_for_invocation(
                &invocation,
                args,
                output_btf_archive_dir,
                &output_btf_archive_path,
            )?;

            let output_tar_path = args.get_output_tar_path();
            let mut output_tar_file = create_output_artifact_tempfile(&output_tar_path)?;
            package_btfhub_tar(
                args,
                &output_btf_archive_path,
                output_tar_file.as_file_mut(),
            )
            .with_context(|| anyhow!("Failed to package btfhub tar"))?;
            output_tar_file.as_file_mut().sync_all()?;
            publish_output_file_artifact_for_invocation(
                &invocation,
                args,
                output_tar_file,
                &output_tar_path,
            )?;
        }
        Ok(())
    })();
    let release_result = claimed_output_artifacts.release();

    match (compile_result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(err), Err(release_err)) => Err(anyhow!(
            "{err}. Failed to release output artifact claims: {release_err}"
        )),
    }
}

/// Pack the object file into a generated package artifact.
fn pack_object_in_config(args: &Options) -> Result<()> {
    let invocation = OutputArtifactInvocation::start(args)?;
    pack_object_in_config_for_invocation(&invocation, args)
}

fn pack_object_in_config_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<()> {
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
    let claim = invocation.claim.clone();
    let release_package_claim =
        claim_output_artifact_for_invocation(invocation, args, &output_package_config_path)?;
    let package_config_str = if args.compile_opts.yaml {
        serde_yaml::to_string(&package_config).unwrap()
    } else {
        serde_json::to_string(&package_config).unwrap()
    };
    let pack_result = (|| -> Result<()> {
        let mut output_package_file = create_output_artifact_tempfile(&output_package_config_path)?;
        output_package_file
            .as_file_mut()
            .write_all(package_config_str.as_bytes())?;
        output_package_file.as_file_mut().sync_all()?;
        publish_output_file_artifact_for_invocation(
            invocation,
            args,
            output_package_file,
            &output_package_config_path,
        )?;
        remove_matching_sibling_package_artifact_for_invocation(invocation, args)?;
        Ok(())
    })();

    if release_package_claim {
        if let Err(release_err) = release_output_artifact_claim(&claim, &output_package_config_path)
        {
            return match pack_result {
                Ok(()) => Err(release_err),
                Err(err) => Err(err.context(format!(
                    "Failed to release output artifact claim: {release_err}"
                ))),
            };
        }
    }

    pack_result
}

fn build_output_artifact_owner(args: &Options) -> Result<OutputArtifactOwner> {
    let source_path = normalize_output_artifact_identity_path(&args.compile_opts.source_path);
    Ok(OutputArtifactOwner {
        object_name: args.object_name.clone(),
        source_path,
        source_snapshot: build_output_artifact_source_snapshot(args)?,
        build_signature: build_output_artifact_build_signature(args),
    })
}

fn normalize_output_artifact_identity_path(path: impl AsRef<Path>) -> String {
    fs::canonicalize(path.as_ref())
        .unwrap_or_else(|_| path.as_ref().to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn normalize_optional_output_artifact_identity_path(path: &str) -> Option<String> {
    if path.is_empty() {
        None
    } else {
        Some(normalize_output_artifact_identity_path(path))
    }
}

fn resolve_output_artifact_tool_path(path: &str, path_env: Option<&OsStr>) -> Option<PathBuf> {
    let tool_path = Path::new(path);
    if tool_path.is_absolute() || path.contains(std::path::MAIN_SEPARATOR) {
        return Some(tool_path.to_path_buf());
    }

    let path_env = path_env?;
    for dir in std::env::split_paths(path_env) {
        let candidate = dir.join(tool_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn normalize_output_artifact_tool_identity_path(path: &str) -> String {
    normalize_output_artifact_tool_identity_path_with_path_env(
        path,
        std::env::var_os("PATH").as_deref(),
    )
}

fn normalize_output_artifact_tool_identity_path_with_path_env(
    path: &str,
    path_env: Option<&OsStr>,
) -> String {
    if let Some(resolved_path) = resolve_output_artifact_tool_path(path, path_env) {
        return normalize_output_artifact_identity_path(resolved_path);
    }

    normalize_output_artifact_identity_path(path)
}

fn build_output_artifact_source_snapshot(args: &Options) -> Result<OutputArtifactSourceSnapshot> {
    let dependency_paths = collect_output_artifact_source_dependency_paths(args)?;
    let mut hasher = Sha256::new();
    hasher.update(b"output-artifact-source-snapshot-v1\0");

    for dependency_path in dependency_paths {
        hasher.update(dependency_path.as_bytes());
        hasher.update(b"\0");
        hash_output_artifact_source_input(&mut hasher, &dependency_path)?;
        hasher.update(b"\0");
    }

    Ok(OutputArtifactSourceSnapshot {
        digest: format!("{:x}", hasher.finalize()),
    })
}

fn collect_output_artifact_source_dependency_paths(args: &Options) -> Result<Vec<String>> {
    let source_path = Path::new(&args.compile_opts.source_path);
    let compile_args = get_bpf_compile_args(args, source_path)?;
    let dependency_file = NamedTempFile::new_in(args.get_workspace_directory())?;
    let mut command = std::process::Command::new(&args.compile_opts.parameters.clang_bin);
    command
        .args(&compile_args)
        .arg("-M")
        .arg("-MF")
        .arg(dependency_file.path())
        .arg("-MT")
        .arg("output-artifact-source-snapshot")
        .arg(source_path);
    handle_std_command_with_log!(
        command,
        "Failed to capture output artifact source dependencies"
    );

    let dependency_file_contents = fs::read_to_string(dependency_file.path())?;
    let mut dependency_paths = BTreeSet::new();
    for dependency_path in parse_output_artifact_dependency_file(&dependency_file_contents)? {
        dependency_paths.insert(normalize_output_artifact_identity_path(dependency_path));
    }
    dependency_paths.insert(normalize_output_artifact_identity_path(source_path));

    if let Some(export_event_header) =
        normalize_optional_output_artifact_identity_path(&args.compile_opts.export_event_header)
    {
        dependency_paths.insert(export_event_header);
    }

    Ok(dependency_paths.into_iter().collect())
}

fn parse_output_artifact_dependency_file(dependency_file_contents: &str) -> Result<Vec<String>> {
    let mut dependency_section = String::new();
    let mut separator_found = false;
    let mut escaped = false;

    for ch in dependency_file_contents.chars() {
        if !separator_found {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                ':' => separator_found = true,
                _ => {}
            }
            continue;
        }
        dependency_section.push(ch);
    }

    if !separator_found {
        bail!("Failed to parse output artifact dependency file");
    }

    let mut flattened_dependencies = String::new();
    let mut chars = dependency_section.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some('\n') => {
                    chars.next();
                    continue;
                }
                Some('\r') => {
                    chars.next();
                    if matches!(chars.peek(), Some('\n')) {
                        chars.next();
                    }
                    continue;
                }
                _ => {}
            }
        }
        flattened_dependencies.push(ch);
    }

    let mut dependencies = Vec::new();
    let mut current = String::new();
    let mut escape_next = false;
    for ch in flattened_dependencies.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' => escape_next = true,
            ch if ch.is_whitespace() => {
                if !current.is_empty() {
                    dependencies.push(current);
                    current = String::new();
                }
            }
            _ => current.push(ch),
        }
    }

    if escape_next {
        current.push('\\');
    }
    if !current.is_empty() {
        dependencies.push(current);
    }

    Ok(dependencies)
}

fn hash_output_artifact_source_input(hasher: &mut Sha256, path: &str) -> Result<()> {
    let mut reader = BufReader::new(fs::File::open(path)?);
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(())
}

fn build_output_artifact_build_signature(args: &Options) -> OutputArtifactBuildSignature {
    OutputArtifactBuildSignature {
        header_only: args.compile_opts.header_only,
        export_event_header: normalize_optional_output_artifact_identity_path(
            &args.compile_opts.export_event_header,
        ),
        wasm_header: args.compile_opts.wasm_header,
        btfgen: args.compile_opts.btfgen,
        btfhub_archive: if args.compile_opts.btfgen {
            normalize_optional_output_artifact_identity_path(&args.compile_opts.btfhub_archive)
        } else {
            None
        },
        generate_package: !args.compile_opts.parameters.no_generate_package_json,
        standalone: args.compile_opts.parameters.standalone,
        additional_cflags: args.compile_opts.parameters.additional_cflags.clone(),
        workspace_path: args
            .compile_opts
            .parameters
            .workspace_path
            .as_deref()
            .map(normalize_output_artifact_identity_path),
        clang_bin: normalize_output_artifact_tool_identity_path(
            &args.compile_opts.parameters.clang_bin,
        ),
        llvm_strip_bin: normalize_output_artifact_tool_identity_path(
            &args.compile_opts.parameters.llvm_strip_bin,
        ),
    }
}

fn build_output_artifact_invocation_id(args: &Options) -> String {
    fs::canonicalize(args.get_workspace_directory())
        .unwrap_or_else(|_| args.get_workspace_directory().to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn build_output_artifact_claim(args: &Options) -> Result<OutputArtifactClaim> {
    Ok(OutputArtifactInvocation::start(args)?.claim)
}

fn find_existing_output_artifact_invocation_started_at(
    args: &Options,
    invocation_id: &str,
    owner: &OutputArtifactOwner,
) -> Result<Option<u64>> {
    let encoded_invocation_id = base64::encode_config(invocation_id, base64::URL_SAFE_NO_PAD);
    let claim_file_name = format!("{encoded_invocation_id}.json");
    let mut started_at_unix_nanos = None;
    let entries = match fs::read_dir(args.get_output_directory()) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let claim_directory_name = entry.file_name();
        let Some(claim_directory_name) = claim_directory_name.to_str() else {
            continue;
        };
        if !claim_directory_name.ends_with(".ecc-owner.claims") {
            continue;
        }

        let claim_path = entry.path().join(&claim_file_name);
        if !claim_path.exists() {
            continue;
        }

        let claim = serde_json::from_str::<OutputArtifactClaim>(&fs::read_to_string(&claim_path)?)
            .with_context(|| {
                anyhow!(
                    "Failed to parse output artifact claim marker {}",
                    claim_path.display()
                )
            })?;
        if !claim.owner.matches_revision(owner) || claim.started_at_unix_nanos == 0 {
            continue;
        }

        started_at_unix_nanos = Some(
            started_at_unix_nanos.map_or(claim.started_at_unix_nanos, |current: u64| {
                current.min(claim.started_at_unix_nanos)
            }),
        );
    }

    Ok(started_at_unix_nanos)
}

fn get_output_artifact_marker_path_from_artifact(artifact_path: impl AsRef<Path>) -> PathBuf {
    let artifact_path = artifact_path.as_ref();
    artifact_path
        .parent()
        .expect("Output artifacts are expected to have a parent directory")
        .join(format!(
            ".{}.ecc-owner.json",
            artifact_path
                .file_name()
                .expect("Output artifacts are expected to have a file name")
                .to_string_lossy()
        ))
}

fn get_output_artifact_claim_directory(artifact_path: impl AsRef<Path>) -> PathBuf {
    get_output_artifact_marker_path_from_artifact(artifact_path).with_extension("claims")
}

fn get_output_artifact_cleanup_reservation_path(artifact_path: impl AsRef<Path>) -> PathBuf {
    get_output_artifact_marker_path_from_artifact(artifact_path).with_extension("cleanup")
}

fn get_output_artifact_claim_path_for_invocation(
    invocation_id: &str,
    artifact_path: impl AsRef<Path>,
) -> PathBuf {
    let encoded_invocation_id = base64::encode_config(invocation_id, base64::URL_SAFE_NO_PAD);
    get_output_artifact_claim_directory(artifact_path).join(format!("{encoded_invocation_id}.json"))
}

fn get_output_artifact_claim_path(args: &Options, artifact_path: impl AsRef<Path>) -> PathBuf {
    get_output_artifact_claim_path_for_invocation(
        &build_output_artifact_invocation_id(args),
        artifact_path,
    )
}

fn build_output_artifact_marker(
    owner: &OutputArtifactOwner,
    finalized_at_unix_nanos: Option<u64>,
) -> OutputArtifactMarker {
    OutputArtifactMarker {
        owner: owner.clone(),
        finalized_at_unix_nanos,
    }
}

fn read_output_artifact_marker(marker_path: impl AsRef<Path>) -> Result<OutputArtifactMarker> {
    let marker_path = marker_path.as_ref();
    serde_json::from_str(&fs::read_to_string(marker_path)?).with_context(|| {
        anyhow!(
            "Failed to parse output artifact owner marker {}",
            marker_path.display()
        )
    })
}

fn read_output_artifact_owner_marker(marker_path: impl AsRef<Path>) -> Result<OutputArtifactOwner> {
    Ok(read_output_artifact_marker(marker_path)?.owner)
}

fn create_output_artifact_marker_tempfile(
    marker_path: impl AsRef<Path>,
    marker: &OutputArtifactMarker,
) -> Result<NamedTempFile> {
    let marker_path = marker_path.as_ref();
    let marker_dir = marker_path
        .parent()
        .expect("Output artifact markers are expected to have a parent directory");
    let mut marker_file = NamedTempFile::new_in(marker_dir)?;
    serde_json::to_writer(marker_file.as_file_mut(), marker)?;
    marker_file.as_file_mut().sync_all()?;
    Ok(marker_file)
}

fn record_output_artifact_finalization_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let artifact_path = artifact_path.as_ref();
    let marker_path = args.get_output_artifact_marker_path(artifact_path);
    let expected_owner = invocation.owner();

    if marker_path.exists() {
        let marker = read_output_artifact_marker(&marker_path)?;
        if !marker.owner.matches_revision(expected_owner)
            && !marker.owner.is_legacy_upgrade_target_for(expected_owner)
            && artifact_path.exists()
        {
            bail!(
                "Refusing to finalize output artifact {} because it belongs to a different source or build",
                artifact_path.display()
            );
        }
    }

    create_output_artifact_marker_tempfile(
        &marker_path,
        &build_output_artifact_marker(invocation.owner(), Some(current_unix_time_nanos())),
    )?
    .persist(&marker_path)
    .map_err(|err| err.error)?;
    Ok(())
}

fn read_output_artifact_claims(
    artifact_path: impl AsRef<Path>,
) -> Result<Vec<OutputArtifactClaim>> {
    let claim_dir = get_output_artifact_claim_directory(artifact_path);
    let mut entries = match fs::read_dir(&claim_dir) {
        Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    entries.sort_by_key(|entry| entry.file_name());

    let mut claims = Vec::new();
    for entry in entries {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let claim_path = entry.path();
        if claim_path
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("json")
        {
            continue;
        }
        let claim = serde_json::from_str(&fs::read_to_string(&claim_path)?).with_context(|| {
            anyhow!(
                "Failed to parse output artifact claim marker {}",
                claim_path.display()
            )
        })?;
        claims.push(claim);
    }
    Ok(claims)
}

fn output_artifact_has_inflight_claims(artifact_path: impl AsRef<Path>) -> Result<bool> {
    let claim_dir = get_output_artifact_claim_directory(artifact_path);
    let entries = match fs::read_dir(&claim_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("tmp")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn create_output_artifact_claim_marker_tempfile(
    claim_path: impl AsRef<Path>,
    claim: &OutputArtifactClaim,
) -> Result<NamedTempFile> {
    let claim_path = claim_path.as_ref();
    let claim_dir = claim_path
        .parent()
        .expect("Output artifact claim markers are expected to have a parent directory");
    fs::create_dir_all(claim_dir)?;
    let mut claim_file = Builder::new()
        .prefix(".tmp-output-artifact-claim-")
        .suffix(".tmp")
        .tempfile_in(claim_dir)?;
    serde_json::to_writer(claim_file.as_file_mut(), claim)?;
    claim_file.as_file_mut().sync_all()?;
    Ok(claim_file)
}

fn create_output_artifact_cleanup_reservation_tempfile(
    reservation_path: impl AsRef<Path>,
) -> Result<NamedTempFile> {
    let reservation_path = reservation_path.as_ref();
    let reservation_dir = reservation_path
        .parent()
        .expect("Output artifact cleanup reservations are expected to have a parent directory");
    let mut reservation_file = Builder::new()
        .prefix(".tmp-output-artifact-cleanup-")
        .suffix(".tmp")
        .tempfile_in(reservation_dir)?;
    reservation_file.as_file_mut().write_all(b"cleanup")?;
    reservation_file.as_file_mut().sync_all()?;
    Ok(reservation_file)
}

fn output_artifact_cleanup_is_reserved(artifact_path: impl AsRef<Path>) -> bool {
    get_output_artifact_cleanup_reservation_path(artifact_path).exists()
}

fn ensure_output_artifact_is_not_being_cleaned_up(
    artifact_path: &Path,
    action: &str,
) -> Result<()> {
    if output_artifact_cleanup_is_reserved(artifact_path) {
        bail!(
            "Refusing to {} {} because it is being cleaned up",
            action,
            artifact_path.display()
        );
    }
    Ok(())
}

struct OutputArtifactCleanupReservationGuard {
    reservation_path: PathBuf,
    released: bool,
}

impl OutputArtifactCleanupReservationGuard {
    fn release(mut self) -> Result<()> {
        self.released = true;
        match fs::remove_file(&self.reservation_path) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

impl Drop for OutputArtifactCleanupReservationGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }

        if let Err(err) = fs::remove_file(&self.reservation_path) {
            if err.kind() != ErrorKind::NotFound {
                error!(
                    "Failed to release output artifact cleanup reservation {}: {err}",
                    self.reservation_path.display()
                );
            }
        }
    }
}

fn try_reserve_output_artifact_cleanup(
    artifact_path: impl AsRef<Path>,
) -> Result<Option<OutputArtifactCleanupReservationGuard>> {
    let artifact_path = artifact_path.as_ref();
    let reservation_path = get_output_artifact_cleanup_reservation_path(artifact_path);
    if reservation_path.exists() {
        return Ok(None);
    }

    let reservation_file = create_output_artifact_cleanup_reservation_tempfile(&reservation_path)?;
    match reservation_file.persist_noclobber(&reservation_path) {
        Ok(_) => {
            #[cfg(test)]
            wait_for_output_artifact_cleanup_reservation(&reservation_path);
            Ok(Some(OutputArtifactCleanupReservationGuard {
                reservation_path,
                released: false,
            }))
        }
        Err(err) if err.error.kind() == ErrorKind::AlreadyExists => Ok(None),
        Err(err) => Err(err.error.into()),
    }
}

fn remove_output_artifact_owner_marker_if_unclaimed(
    owner: &OutputArtifactOwner,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let artifact_path = artifact_path.as_ref();
    let Some(cleanup_reservation) = try_reserve_output_artifact_cleanup(artifact_path)? else {
        return Ok(());
    };
    let cleanup_result = (|| -> Result<()> {
        if artifact_path.exists()
            || output_artifact_has_inflight_claims(artifact_path)?
            || !read_output_artifact_claims(artifact_path)?.is_empty()
        {
            return Ok(());
        }

        let marker_path = get_output_artifact_marker_path_from_artifact(artifact_path);
        if !marker_path.exists() {
            return Ok(());
        }

        let marker = read_output_artifact_owner_marker(&marker_path)?;
        if marker.matches_revision(owner) {
            fs::remove_file(marker_path)?;
        }
        Ok(())
    })();
    let release_result = cleanup_reservation.release();

    match (cleanup_result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(err), Err(release_err)) => Err(err.context(format!(
            "Failed to release output artifact cleanup reservation: {release_err}"
        ))),
    }
}

fn publish_output_artifact_owner_marker_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let artifact_path = artifact_path.as_ref();
    let owner = invocation.owner();
    let marker_path = args.get_output_artifact_marker_path(artifact_path);
    if marker_path.exists() {
        let marker = read_output_artifact_marker(&marker_path)?;
        if marker.owner.matches_revision(owner) {
            return Ok(());
        }
        let claims = read_output_artifact_claims(artifact_path)?;
        if marker.owner.is_legacy_upgrade_target_for(owner) && artifact_path.exists() {
            if claims.iter().any(|claim| {
                !claim.owner.matches_revision(owner)
                    && !claim.owner.is_legacy_upgrade_target_for(owner)
            }) {
                return Err(output_artifact_conflict_error(
                    artifact_path,
                    "claim output artifact",
                ));
            }
            return Ok(());
        }
        if artifact_path.exists()
            || claims.iter().any(|claim| {
                !claim.owner.matches_revision(owner)
                    && !claim.owner.is_legacy_upgrade_target_for(owner)
            })
        {
            return Err(output_artifact_conflict_error(
                artifact_path,
                "claim output artifact",
            ));
        }
        create_output_artifact_marker_tempfile(
            &marker_path,
            &build_output_artifact_marker(owner, None),
        )?
        .persist(&marker_path)
        .map_err(|err| err.error)?;
        return Ok(());
    }

    let marker_file = create_output_artifact_marker_tempfile(
        &marker_path,
        &build_output_artifact_marker(owner, None),
    )?;
    #[cfg(test)]
    wait_for_output_artifact_marker_publish(&marker_path);
    match marker_file.persist_noclobber(&marker_path) {
        Ok(_) => Ok(()),
        Err(err) if err.error.kind() == ErrorKind::AlreadyExists => {
            let marker = read_output_artifact_marker(&marker_path)?;
            let claims = read_output_artifact_claims(artifact_path)?;
            if marker.owner.is_legacy_upgrade_target_for(owner) && artifact_path.exists() {
                if claims.iter().any(|claim| {
                    !claim.owner.matches_revision(owner)
                        && !claim.owner.is_legacy_upgrade_target_for(owner)
                }) {
                    return Err(output_artifact_conflict_error(
                        artifact_path,
                        "claim output artifact",
                    ));
                }
                return Ok(());
            }
            if !marker.owner.matches_revision(owner)
                && (artifact_path.exists()
                    || claims.iter().any(|claim| {
                        !claim.owner.matches_revision(owner)
                            && !claim.owner.is_legacy_upgrade_target_for(owner)
                    }))
            {
                return Err(output_artifact_conflict_error(
                    artifact_path,
                    "claim output artifact",
                ));
            }
            if !marker.owner.matches_revision(owner) {
                create_output_artifact_marker_tempfile(
                    &marker_path,
                    &build_output_artifact_marker(owner, marker.finalized_at_unix_nanos),
                )?
                .persist(&marker_path)
                .map_err(|persist_err| persist_err.error)?;
            }
            Ok(())
        }
        Err(err) => Err(err.error.into()),
    }
}

fn publish_output_artifact_owner_marker(
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let invocation = OutputArtifactInvocation::start(args)?;
    publish_output_artifact_owner_marker_for_invocation(&invocation, args, artifact_path)
}

fn release_output_artifact_claim(
    claim: &OutputArtifactClaim,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let artifact_path = artifact_path.as_ref();
    let claim_path =
        get_output_artifact_claim_path_for_invocation(&claim.invocation_id, artifact_path);
    #[cfg(test)]
    fail_output_artifact_claim_release_if_configured(&claim_path)?;
    match fs::remove_file(&claim_path) {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let claim_dir = get_output_artifact_claim_directory(artifact_path);
    let remaining_claims = read_output_artifact_claims(artifact_path)?;
    if remaining_claims.is_empty() {
        remove_output_artifact_owner_marker_if_unclaimed(&claim.owner, artifact_path)?;
        match fs::remove_dir(&claim_dir) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) if io_error_is_directory_not_empty(&err) => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

#[cfg(test)]
fn wait_for_output_artifact_marker_publish(marker_path: &Path) {
    let barrier = OUTPUT_ARTIFACT_MARKER_PUBLISH_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some(barrier) = barrier.filter(|barrier| barrier.marker_path == marker_path) {
        barrier.barrier.wait();
    }
}

#[cfg(test)]
pub(crate) fn set_output_artifact_marker_publish_barrier(
    marker_path: Option<(PathBuf, Arc<Barrier>)>,
) {
    *OUTPUT_ARTIFACT_MARKER_PUBLISH_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = marker_path.map(
        |(marker_path, barrier)| OutputArtifactMarkerPublishBarrier {
            marker_path,
            barrier,
        },
    );
}

#[cfg(test)]
fn wait_for_output_artifact_claim_publish(claim_path: &Path) {
    let barrier = OUTPUT_ARTIFACT_CLAIM_PUBLISH_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some(barrier) = barrier.filter(|barrier| barrier.claim_path == claim_path) {
        barrier.entered.wait();
        barrier.release.wait();
    }
}

#[cfg(test)]
pub(crate) fn set_output_artifact_claim_publish_barrier(
    claim_path: Option<(PathBuf, Arc<Barrier>, Arc<Barrier>)>,
) {
    *OUTPUT_ARTIFACT_CLAIM_PUBLISH_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() =
        claim_path.map(
            |(claim_path, entered, release)| OutputArtifactClaimPublishBarrier {
                claim_path,
                entered,
                release,
            },
        );
}

#[cfg(test)]
fn fail_output_artifact_claim_release_if_configured(claim_path: &Path) -> Result<()> {
    let failure = OUTPUT_ARTIFACT_CLAIM_RELEASE_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some(failure) = failure.filter(|failure| failure.claim_path == claim_path) {
        bail!("{}", failure.message);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_output_artifact_claim_release_failure(failure: Option<(PathBuf, String)>) {
    *OUTPUT_ARTIFACT_CLAIM_RELEASE_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = failure.map(|(claim_path, message)| OutputArtifactClaimReleaseFailure {
        claim_path,
        message,
    });
}

#[cfg(test)]
fn wait_for_output_artifact_cleanup_reservation(reservation_path: &Path) {
    let barrier = OUTPUT_ARTIFACT_CLEANUP_RESERVATION_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some(barrier) = barrier.filter(|barrier| barrier.reservation_path == reservation_path) {
        barrier.entered.wait();
        barrier.release.wait();
    }
}

#[cfg(test)]
pub(crate) fn set_output_artifact_cleanup_reservation_barrier(
    reservation_path: Option<(PathBuf, Arc<Barrier>, Arc<Barrier>)>,
) {
    *OUTPUT_ARTIFACT_CLEANUP_RESERVATION_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() = reservation_path.map(|(reservation_path, entered, release)| {
        OutputArtifactCleanupReservationBarrier {
            reservation_path,
            entered,
            release,
        }
    });
}

#[cfg(test)]
fn wait_for_output_object_publish(artifact_path: &Path) {
    let barrier = OUTPUT_OBJECT_PUBLISH_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some(barrier) = barrier.filter(|barrier| barrier.artifact_path == artifact_path) {
        barrier.entered.wait();
        barrier.release.wait();
    }
}

#[cfg(test)]
pub(crate) fn set_output_object_publish_barrier(
    artifact_path: Option<(PathBuf, Arc<Barrier>, Arc<Barrier>)>,
) {
    *OUTPUT_OBJECT_PUBLISH_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap() =
        artifact_path.map(
            |(artifact_path, entered, release)| OutputObjectPublishBarrier {
                artifact_path,
                entered,
                release,
            },
        );
}

pub(crate) fn ensure_output_artifact_can_be_written(
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let invocation = OutputArtifactInvocation::start(args)?;
    ensure_output_artifact_can_be_written_for_invocation(&invocation, args, artifact_path)
}

fn ensure_output_artifact_can_be_written_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    let artifact_path = artifact_path.as_ref();
    let expected_owner = invocation.owner();
    let action = if artifact_path.exists() {
        "overwrite existing output artifact"
    } else {
        "claim output artifact"
    };
    ensure_output_artifact_is_not_being_cleaned_up(artifact_path, action)?;
    let marker_path = args.get_output_artifact_marker_path(artifact_path);
    let claims = read_output_artifact_claims(artifact_path)?;
    if claims.iter().any(|claim| {
        !claim.owner.matches_revision(expected_owner)
            && !claim.owner.is_legacy_upgrade_target_for(expected_owner)
    }) {
        return Err(output_artifact_conflict_error(artifact_path, action));
    }

    if !artifact_path.exists() && !marker_path.exists() && claims.is_empty() {
        return Ok(());
    }

    if artifact_path.exists() && !marker_path.exists() {
        bail!(
            "Refusing to {} {} because it is unclaimed; use a dedicated output directory or remove it first",
            action,
            artifact_path.display()
        );
    }

    if !marker_path.exists() {
        return Ok(());
    }

    let marker = read_output_artifact_owner_marker(&marker_path)?;
    if !marker.matches_revision(expected_owner)
        && !marker.is_legacy_upgrade_target_for(expected_owner)
        && artifact_path.exists()
    {
        return Err(output_artifact_conflict_error(artifact_path, action));
    }

    Ok(())
}

pub(crate) fn write_output_artifact_owner_marker(
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<()> {
    publish_output_artifact_owner_marker(args, artifact_path)
}

fn claim_output_artifact(args: &Options, artifact_path: impl AsRef<Path>) -> Result<bool> {
    let invocation = OutputArtifactInvocation::start(args)?;
    claim_output_artifact_for_invocation(&invocation, args, artifact_path)
}

fn claim_output_artifact_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
    artifact_path: impl AsRef<Path>,
) -> Result<bool> {
    let artifact_path = artifact_path.as_ref();
    ensure_output_artifact_can_be_written_for_invocation(invocation, args, artifact_path)?;
    let claim = invocation.claim.clone();
    let claim_path = get_output_artifact_claim_path(args, artifact_path);
    if claim_path.exists() {
        return Ok(false);
    }

    let claim_file = create_output_artifact_claim_marker_tempfile(&claim_path, &claim)?;
    #[cfg(test)]
    wait_for_output_artifact_claim_publish(&claim_path);
    match claim_file.persist_noclobber(&claim_path) {
        Ok(_) => {}
        Err(err) if err.error.kind() == ErrorKind::AlreadyExists => {
            ensure_output_artifact_can_be_written_for_invocation(invocation, args, artifact_path)?;
            return Ok(false);
        }
        Err(err) => return Err(err.error.into()),
    }

    let action = if artifact_path.exists() {
        "overwrite existing output artifact"
    } else {
        "claim output artifact"
    };
    if let Err(err) = ensure_output_artifact_is_not_being_cleaned_up(artifact_path, action) {
        if let Err(release_err) = release_output_artifact_claim(&claim, artifact_path) {
            return Err(err.context(format!(
                "Failed to release output artifact claim after reservation conflict: {release_err}"
            )));
        }
        return Err(err);
    }

    if let Err(err) =
        publish_output_artifact_owner_marker_for_invocation(invocation, args, artifact_path)
    {
        if let Err(release_err) = release_output_artifact_claim(&claim, artifact_path) {
            return Err(err.context(format!(
                "Failed to release output artifact claim after publish failure: {release_err}"
            )));
        }
        return Err(err);
    }

    Ok(true)
}

fn should_preserve_active_sibling_package_artifact(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<bool> {
    if args.compile_opts.parameters.no_generate_package_json {
        return Ok(false);
    }

    let sibling_package_config_path = args.get_output_sibling_package_config_path();
    let expected_owner = invocation.owner();
    let sibling_claims = read_output_artifact_claims(&sibling_package_config_path)?;
    if sibling_claims
        .iter()
        .any(|claim| claim.owner.matches_package_lineage(&expected_owner))
    {
        return Ok(true);
    }

    if !output_artifact_has_inflight_claims(&sibling_package_config_path)? {
        return Ok(false);
    }

    let sibling_marker_path = args.get_output_sibling_package_marker_path();
    if !sibling_marker_path.exists() {
        return Ok(false);
    }

    Ok(read_output_artifact_marker(&sibling_marker_path)?
        .owner
        .matches_package_lineage(&expected_owner))
}

fn collect_requested_output_artifacts(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<Vec<PathBuf>> {
    let mut artifact_paths = vec![args.get_output_object_path(), args.get_output_config_path()];

    if !args.compile_opts.parameters.no_generate_package_json {
        artifact_paths.push(args.get_output_package_config_path());
        if should_preserve_active_sibling_package_artifact(invocation, args)? {
            artifact_paths.push(args.get_output_sibling_package_config_path());
        }
    }
    if args.compile_opts.parameters.standalone {
        artifact_paths.push(args.get_standalone_source_file_path());
        artifact_paths.push(args.get_standalone_executable_path());
    }
    if args.compile_opts.wasm_header {
        artifact_paths.push(args.get_wasm_header_path());
    }
    if args.compile_opts.btfgen {
        artifact_paths.push(args.get_output_btf_archive_directory());
        artifact_paths.push(args.get_output_tar_path());
    }

    Ok(artifact_paths)
}

fn claim_requested_output_artifacts(args: &Options) -> Result<OutputArtifactClaimsGuard> {
    let invocation = OutputArtifactInvocation::start(args)?;
    claim_requested_output_artifacts_for_invocation(&invocation, args)
}

fn claim_requested_output_artifacts_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<OutputArtifactClaimsGuard> {
    let artifact_paths = collect_requested_output_artifacts(invocation, args)?;
    for artifact_path in &artifact_paths {
        ensure_output_artifact_can_be_written_for_invocation(invocation, args, artifact_path)?;
    }

    let mut claims = OutputArtifactClaimsGuard::new(invocation);
    for artifact_path in artifact_paths {
        if let Err(err) = claim_output_artifact_for_invocation(invocation, args, &artifact_path) {
            let rollback_err = claims.release_tracked_claims();
            return match rollback_err {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(anyhow!(
                    "{err}. Failed to rollback output artifact claims: {rollback_err}"
                )),
            };
        }
        claims.track(artifact_path);
    }

    Ok(claims)
}

fn remove_matching_sibling_package_artifact_for_invocation(
    invocation: &OutputArtifactInvocation,
    args: &Options,
) -> Result<()> {
    let sibling_package_config_path = args.get_output_sibling_package_config_path();
    let Some(cleanup_reservation) =
        try_reserve_output_artifact_cleanup(&sibling_package_config_path)?
    else {
        info!(
            "Leaving sibling package artifact {} in place because it is being cleaned up",
            sibling_package_config_path.display()
        );
        return Ok(());
    };
    let cleanup_result = (|| -> Result<()> {
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

        let sibling_marker = read_output_artifact_marker(&sibling_marker_path)?;
        let expected_owner = invocation.owner();
        if !sibling_marker
            .owner
            .matches_package_lineage(&expected_owner)
        {
            info!(
                "Leaving sibling package artifact {} in place because it belongs to a different build",
                sibling_package_config_path.display()
            );
            return Ok(());
        }

        if output_artifact_has_inflight_claims(&sibling_package_config_path)? {
            info!(
                "Leaving sibling package artifact {} in place because a claim is still being published",
                sibling_package_config_path.display()
            );
            return Ok(());
        }

        if !read_output_artifact_claims(&sibling_package_config_path)?.is_empty() {
            info!(
                "Leaving sibling package artifact {} in place because it is still actively claimed",
                sibling_package_config_path.display()
            );
            return Ok(());
        }

        if sibling_marker
            .finalized_at_unix_nanos
            .is_some_and(|finalized_at| finalized_at >= invocation.started_at_unix_nanos)
        {
            info!(
                "Leaving sibling package artifact {} in place because it was finalized by an overlapping build",
                sibling_package_config_path.display()
            );
            return Ok(());
        }

        info!(
            "Removing stale package artifact {}...",
            sibling_package_config_path.display()
        );
        fs::remove_file(&sibling_package_config_path)?;
        fs::remove_file(sibling_marker_path)?;
        match fs::remove_dir(get_output_artifact_claim_directory(
            args.get_output_sibling_package_config_path(),
        )) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) if io_error_is_directory_not_empty(&err) => {}
            Err(err) => return Err(err.into()),
        }
        Ok(())
    })();
    let release_result = cleanup_reservation.release();

    match (cleanup_result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(err), Err(release_err)) => Err(err.context(format!(
            "Failed to release output artifact cleanup reservation: {release_err}"
        ))),
    }
}

#[cfg(test)]
mod tests;
