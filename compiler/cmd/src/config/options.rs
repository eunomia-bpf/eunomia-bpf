//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::path::{Path, PathBuf};

use super::CompileArgs;
use anyhow::{anyhow, Result};
use tempfile::TempDir;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageFormat {
    Json,
    Yaml,
}

impl PackageFormat {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Json => "package.json",
            Self::Yaml => "package.yaml",
        }
    }

    pub fn sibling(self) -> Self {
        match self {
            Self::Json => Self::Yaml,
            Self::Yaml => Self::Json,
        }
    }
}

pub struct Options {
    pub tmpdir: TempDir,
    pub compile_opts: CompileArgs,
    pub object_name: String,
}

impl Options {
    pub(crate) fn init(mut opts: CompileArgs, tmp_workspace: TempDir) -> Result<Options> {
        check_compile_opts(&mut opts)?;
        let object_name = PathBuf::from(&opts.source_path)
            .file_name()
            .ok_or_else(|| anyhow!("Source path should be a file, and thus it must have filename"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to cast to string"))?
            .split('.')
            .next()
            .unwrap()
            .to_string();
        Ok(Options {
            compile_opts: opts.clone(),
            tmpdir: tmp_workspace,
            object_name,
        })
    }
    #[allow(unused)]
    pub fn get_workspace_directory(&self) -> &Path {
        self.tmpdir.path()
    }

    /// Get the output directory of the current compilation
    pub fn get_output_directory(&self) -> PathBuf {
        if let Some(out_path) = &self.compile_opts.output_path {
            PathBuf::from(out_path)
        } else {
            PathBuf::from(&self.compile_opts.source_path)
                .parent()
                .expect("Source path should be a file, and thus it must have parent directory")
                .to_path_buf()
        }
    }

    /// Get output path for json: output.meta.json
    pub fn get_output_config_path(&self) -> PathBuf {
        let output_path = self.get_output_directory();

        if self.compile_opts.yaml {
            output_path.join(format!("{}.skel.yaml", self.object_name))
        } else {
            output_path.join(format!("{}.skel.json", self.object_name))
        }
    }
    /// Get output path for bpf object: output.bpf.o  
    pub fn get_output_object_path(&self) -> PathBuf {
        self.get_output_directory()
            .join(format!("{}.bpf.o", self.object_name))
    }

    pub fn get_output_tar_path(&self) -> PathBuf {
        self.get_output_directory()
            .join(format!("{}.tar", self.object_name))
    }

    pub fn get_output_btf_archive_directory(&self) -> PathBuf {
        self.get_output_directory()
            .join(format!("{}.custom-archive", self.object_name))
    }

    pub fn package_format(&self) -> PackageFormat {
        if self.compile_opts.yaml {
            PackageFormat::Yaml
        } else {
            PackageFormat::Json
        }
    }

    pub fn get_output_package_config_path_for(&self, package_format: PackageFormat) -> PathBuf {
        self.get_output_directory().join(package_format.file_name())
    }

    pub fn get_output_package_config_path(&self) -> PathBuf {
        self.get_output_package_config_path_for(self.package_format())
    }

    pub fn get_output_sibling_package_config_path(&self) -> PathBuf {
        self.get_output_package_config_path_for(self.package_format().sibling())
    }

    pub fn get_output_package_marker_path_for(&self, package_format: PackageFormat) -> PathBuf {
        self.get_output_artifact_marker_path(
            self.get_output_package_config_path_for(package_format),
        )
    }

    pub fn get_output_package_marker_path(&self) -> PathBuf {
        self.get_output_package_marker_path_for(self.package_format())
    }

    pub fn get_output_sibling_package_marker_path(&self) -> PathBuf {
        self.get_output_package_marker_path_for(self.package_format().sibling())
    }

    pub fn get_output_artifact_marker_path(&self, artifact_path: impl AsRef<Path>) -> PathBuf {
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

    pub fn get_wasm_header_path(&self) -> PathBuf {
        self.get_output_directory().join("ewasm-skel.h")
    }
    pub fn get_source_file_temp_path(&self) -> PathBuf {
        self.get_workspace_directory()
            .join(format!("{}.temp.c", self.object_name))
    }
    pub fn get_standalone_executable_path(&self) -> PathBuf {
        self.get_output_directory()
            .join(format!("{}.out", self.object_name))
    }
    pub fn get_standalone_source_file_path(&self) -> PathBuf {
        self.get_output_directory()
            .join(format!("{}.standalone.c", self.object_name))
    }
}

fn check_compile_opts(opts: &mut CompileArgs) -> Result<()> {
    validate_output_mode_combinations(opts)?;
    if opts.header_only {
        // treat header as a source file
        opts.export_event_header.clone_from(&opts.source_path);
    }
    Ok(())
}

fn validate_output_mode_combinations(opts: &CompileArgs) -> Result<()> {
    if opts.yaml {
        for (enabled, flag) in [
            (opts.wasm_header, "--wasm-header"),
            (opts.parameters.standalone, "--standalone"),
            (opts.btfgen, "--btfgen"),
        ] {
            if enabled {
                return Err(anyhow!(
                    "{flag} currently requires JSON package output and cannot be combined with --yaml"
                ));
            }
        }
    }

    if opts.parameters.no_generate_package_json {
        for (enabled, flag) in [
            (opts.parameters.standalone, "--standalone"),
            (opts.wasm_header, "--wasm-header"),
            (opts.btfgen, "--btfgen"),
        ] {
            if enabled {
                return Err(anyhow!(
                    "{flag} requires a generated package artifact and cannot be combined with --no-generate-package-json"
                ));
            }
        }
    }

    Ok(())
}
