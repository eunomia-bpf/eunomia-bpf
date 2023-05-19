//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::path::{Path, PathBuf};

use super::CompileArgs;
use anyhow::{anyhow, Result};
use tempfile::TempDir;

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

    pub fn get_output_package_config_path(&self) -> PathBuf {
        self.get_output_directory().join("package.json")
    }

    pub fn get_wasm_header_path(&self) -> PathBuf {
        self.get_output_directory().join("ewasm-skel.h")
    }
    pub fn get_source_file_temp_path(&self) -> PathBuf {
        self.get_output_directory().join("temp.c")
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
    if opts.header_only {
        // treat header as a source file
        opts.export_event_header.clone_from(&opts.source_path);
    }
    Ok(())
}
