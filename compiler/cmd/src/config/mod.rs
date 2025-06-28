//! SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use fs_extra::dir::CopyOptions;
use log::debug;
use rust_embed::RustEmbed;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::result::Result::Ok;
use std::{fs, path};
use tar::Builder;
use tempfile::TempDir;

use crate::handle_runscrpt_with_log;
use crate::helper::{get_eunomia_data_dir, get_target_arch};

pub(crate) mod options;

pub(crate) use self::options::Options;

pub struct EunomiaWorkspace {
    pub options: Options,
}

impl EunomiaWorkspace {
    pub fn init(opts: CompileArgs) -> Result<EunomiaWorkspace> {
        // create workspace
        let tmp_workspace = TempDir::new().with_context(|| {
            anyhow!("Failed to create temporary directory to put workspace things")
        })?;
        if let Some(ref p) = opts.parameters.workspace_path {
            let src = Path::new(p);
            fs_extra::dir::copy(src, tmp_workspace.path(), &CopyOptions::default())?;
        } else {
            init_eunomia_workspace(&tmp_workspace)?
        }
        Ok(EunomiaWorkspace {
            options: Options::init(opts, tmp_workspace)?,
        })
    }
}

/// The eunomia-bpf compile tool
///
/// pack ebpf skeleton in config file with zlib compression and base64 encoding
#[derive(Parser, Debug, Default, Clone)]
#[command(
    author,
    version,
    about = "eunomia-bpf compiler",
    long_about = "see https://github.com/eunomia-bpf/eunomia-bpf for more information"
)]
pub struct CompileArgs {
    #[arg(help = "path of the bpf.c file to compile")]
    pub source_path: String,

    #[arg(default_value_t = ("").to_string(), help = "path of the bpf.h header for defining event struct")]
    pub export_event_header: String,

    #[arg(
        short,
        long,
        help = "A directory to put the generated files; If not provided, will use the source location"
    )]
    pub output_path: Option<String>,

    #[arg(short, long, default_value_t = false, help = "Show more logs")]
    pub verbose: bool,

    #[arg(
        short,
        long,
        default_value_t = false,
        help = "output config skel file in yaml instead of JSON"
    )]
    pub yaml: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "generate a bpf object for struct definition with header file only"
    )]
    pub header_only: bool,

    #[arg(long, default_value_t = false, help = "generate wasm include header")]
    pub wasm_header: bool,

    #[arg(
        short,
        long,
        default_value_t = false,
        help = "fetch custom btfhub archive file"
    )]
    pub btfgen: bool,

    #[arg(long, default_value_t = format!("{}/btfhub-archive", get_eunomia_data_dir().unwrap().to_string_lossy()), help = "directory to save btfhub archive file")]
    pub btfhub_archive: String,
    /// parameters related to compilation
    #[clap(flatten)]
    pub parameters: CompileExtraArgs,
}

#[derive(Parser, Debug, Default, Clone)]
pub struct CompileExtraArgs {
    #[arg(short, long, help = "custom workspace path")]
    pub workspace_path: Option<String>,

    #[arg(short, long, help = "additional c flags for clang",action = ArgAction::Append)]
    pub additional_cflags: Vec<String>,

    #[arg(short, long, default_value_t = ("clang").to_string(), help = "path of clang binary")]
    pub clang_bin: String,

    #[arg(short, long, default_value_t = ("llvm-strip").to_string(), help = "path of the llvm-strip binary")]
    pub llvm_strip_bin: String,

    #[arg(
        short,
        long,
        default_value_t = false,
        help = "Don't generate a `package.json` containing the binary of the ELF file of the ebpf program"
    )]
    pub no_generate_package_json: bool,

    #[arg(
        long,
        short = 's',
        default_value_t = false,
        help = "Produce standalone executable; Can only be used when `no_generate_package_json` is disabled",
        conflicts_with = "no_generate_package_json"
    )]
    pub standalone: bool,
}

/// download the btfhub archives
pub fn fetch_btfhub_repo(args: &CompileArgs) -> Result<String> {
    if Path::new(&args.btfhub_archive).exists() {
        Ok(format!(
            "skip: btfhub-archive directory already exist in {}",
            &args.btfhub_archive
        ))
    } else {
        let command = format!(
            "git clone --depth 1 https://github.com/aquasecurity/btfhub-archive {} && rm -rf {}/.git",
            &args.btfhub_archive, &args.btfhub_archive
        );
        let output = handle_runscrpt_with_log!(command, "Failed to fetch btfhub archive");
        Ok(output)
    }
}

pub fn generate_tailored_btf(args: &Options) -> Result<String> {
    let bpftool_path =
        get_bpftool_path(&args.tmpdir).with_context(|| anyhow!("Failed to load bpftool"))?;

    let btf_archive_path = Path::new(&args.compile_opts.btfhub_archive);
    let btf_tmp = args.tmpdir.path();

    let custom_archive_path = args.get_output_directory().join("custom-archive");
    let command = format!(
        r#"
        cp -r {} {}/btfhub-archive
        find {} -name "*.tar.xz" | \
        xargs -P 8 -I fileName sh -c 'tar xvfJ "fileName" -C "$(dirname "fileName")" && rm "fileName"'
        find {} -name "*.btf" | \
        xargs -P 8 -I fileName sh -c '{} gen min_core_btf "fileName" "fileName" {}'
        mkdir -p {} && cp -r {}/btfhub-archive {}
        "#,
        btf_archive_path.to_string_lossy(),
        btf_tmp.to_string_lossy(),
        btf_tmp.to_string_lossy(),
        btf_tmp.to_string_lossy(),
        bpftool_path.to_string_lossy(),
        args.get_output_object_path().to_string_lossy(),
        custom_archive_path.to_string_lossy(),
        btf_tmp.to_string_lossy(),
        custom_archive_path.to_string_lossy()
    );

    let output = handle_runscrpt_with_log!(command, "Failed to generate tailored btf files");

    Ok(output)
}

pub fn package_btfhub_tar(args: &Options) -> Result<()> {
    let tar_path = args.get_output_tar_path();
    let btf_path = args.get_output_directory().join("custom-archive");
    let package =
        fs::File::create(tar_path).with_context(|| anyhow!("Failed to create the tar"))?;

    let mut tar = Builder::new(package);
    let mut object = fs::File::open(args.get_output_object_path())
        .with_context(|| anyhow!("Failed to open the object file for putting in the tar"))?;
    let mut json = fs::File::open(args.get_output_package_config_path())
        .with_context(|| anyhow!("Failed to open the package json to put in the tar"))?;

    tar.append_dir_all(".", btf_path)
        .with_context(|| anyhow!("Failed to add btf archives into tar"))?;
    tar.append_file("package.json", &mut json)
        .with_context(|| anyhow!("Failed to add package.json into tar"))?;
    tar.append_file(&args.object_name, &mut object)
        .with_context(|| anyhow!("Failed to add target object into the tar"))?;
    tar.finish()
        .with_context(|| anyhow!("Failed to write out the tar"))?;
    Ok(())
}

/// Get include paths from clang
pub fn get_bpf_sys_include_args(args: &CompileArgs) -> Result<Vec<String>> {
    let mut command = args.parameters.clang_bin.clone();
    command += r#" -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'
     "#;
    let output = handle_runscrpt_with_log!(command, "Failed to get bpf sys include");
    Ok(output
        .chars()
        .map(|x| match x {
            '\n' => ' ',
            _ => x,
        })
        .collect::<String>()
        .split_ascii_whitespace()
        .map(|s| s.to_string())
        .collect())
}

/// Get eunomia home include dirs
pub fn get_eunomia_include_args(args: &Options) -> Result<Vec<String>> {
    let eunomia_tmp_workspace = args.tmpdir.path();
    let eunomia_include = path::Path::new(&eunomia_tmp_workspace);
    let eunomia_include = eunomia_include
        .canonicalize()
        .with_context(|| anyhow!("Failed to get the absolute path of eunomia's include"))?;
    let eunomia_include = eunomia_include.join("include");
    let vmlinux_include = eunomia_include.join("vmlinux").join(get_target_arch());
    Ok(vec![
        format!("-I{}", eunomia_include.to_string_lossy()),
        format!("-I{}", vmlinux_include.to_string_lossy()),
    ])
}

/// Get eunomia bpftool path
pub fn get_bpftool_path(tmp_workspace: &TempDir) -> Result<PathBuf> {
    let bpftool = tmp_workspace
        .path()
        .join("bin")
        .join("bpftool")
        .canonicalize()
        .with_context(|| anyhow!("Failed to get the absolute path of bpftool"))?;
    let f = std::fs::File::open(&bpftool)?;
    let metadata = f.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o744);
    std::fs::set_permissions(&bpftool, permissions)?;
    Ok(bpftool)
}

/// Get base dir of source path as include args
pub fn get_base_dir_include_args(source_path: impl AsRef<Path>) -> Result<Vec<String>> {
    // add base dir as include path
    let base_dir = path::Path::new(source_path.as_ref())
        .parent()
        .ok_or_else(|| anyhow!("Source path is expected to have a parent directory"))?;
    let base_dir = if base_dir == path::Path::new("") {
        path::Path::new("./")
    } else {
        base_dir
    };
    let base_dir = match fs::canonicalize(base_dir) {
        Ok(p) => p,
        Err(e) => {
            bail!("Cannot find compile dir: {}", e);
        }
    };
    Ok(vec![format!("-I{}", base_dir.to_string_lossy())])
}

/// embed workspace
#[derive(RustEmbed)]
#[folder = "$OUT_DIR/workspace/"]
struct Workspace;

pub fn init_eunomia_workspace(tmp_workspace: &TempDir) -> Result<()> {
    let eunomia_tmp_workspace = tmp_workspace.path();

    for file in Workspace::iter() {
        let file_path = eunomia_tmp_workspace.join(file.as_ref());
        let file_dir = file_path.parent().with_context(||anyhow!("All files in the bundled workspace are expected to have a parent directory, but {:?} doesn't have",file_path))?;
        if !file_dir.exists() {
            std::fs::create_dir_all(file_dir).with_context(|| {
                anyhow!("Failed to create the parent directory of {:?}", file_path)
            })?;
        }
        let content = Workspace::get(file.as_ref()).unwrap();
        std::fs::write(&file_path, content.data.as_ref())
            .with_context(|| anyhow!("Failed to write out file {:?}", file_path))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests;
