mod compile_bpf;
mod config;
mod document_parser;
mod export_types;

use anyhow::Result;
use clap::Parser;
use compile_bpf::*;
use config::{init_eunomia_workspace, CompileOptions, Options};
use eunomia_rs::{copy_dir_all, TempDir};
use std::path::Path;

fn main() -> Result<()> {
    let args = CompileOptions::parse();

    let tmp_workspace = TempDir::new().unwrap();

    let opts = Options {
        compile_opts: args.clone(),
        tmpdir: tmp_workspace,
    };

    if let Some(ref p) = args.parameters.workspace_path {
        let src = Path::new(p);
        copy_dir_all(src, opts.tmpdir.path()).unwrap();
    } else {
        init_eunomia_workspace(&opts.tmpdir)?
    }

    compile_bpf(&opts)?;

    if !args.parameters.subskeleton {
        pack_object_in_config(&opts)?;
    }

    opts.tmpdir.close()?;

    Ok(())
}
