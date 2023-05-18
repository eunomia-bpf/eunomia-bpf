use std::path::PathBuf;

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
            .unwrap()
            .to_str()
            .ok_or_else(|| anyhow!("Failed to cast to string"))?
            .to_string();
        Ok(Options {
            compile_opts: opts.clone(),
            tmpdir: tmp_workspace,
            object_name,
        })
    }

    /// Get the output directory of the current compilation
    pub fn get_output_directory(&self) -> PathBuf {
        if let Some(out_path) = &self.compile_opts.output_path {
            PathBuf::from(out_path)
        } else {
            PathBuf::from(&self.compile_opts.source_path)
                .parent()
                .unwrap()
                .to_path_buf()
        }
    }

    /// Get output path for json: output.meta.json
    pub fn get_output_config_path(&self) -> PathBuf {
        let output_path = self.get_output_directory();
        let output_json_path = if self.compile_opts.yaml {
            output_path.join(format!("{}.skel.yaml", self.object_name))
        } else {
            output_path.join(format!("{}.skel.json", self.object_name))
        };
        output_json_path
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
}

fn check_compile_opts(opts: &mut CompileArgs) -> Result<()> {
    if opts.header_only {
        // treat header as a source file
        opts.export_event_header.clone_from(&opts.source_path);
    }
    Ok(())
}
