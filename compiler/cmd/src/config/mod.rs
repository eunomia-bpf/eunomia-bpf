//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{bail, Result};
use clap::Parser;
use fs_extra::dir::CopyOptions;
use log::debug;
use rust_embed::RustEmbed;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::result::Result::Ok;
use std::{fs, path};
use tar::Builder;
use tempfile::TempDir;

use crate::handle_runscrpt_with_log;
use crate::helper::get_eunomia_data_dir;

pub struct Options {
    pub tmpdir: TempDir,
    pub compile_opts: CompileArgs,
}

impl Options {
    fn check_compile_opts(opts: &mut CompileArgs) -> Result<()> {
        if opts.header_only {
            // treat header as a source file
            opts.export_event_header.clone_from(&opts.source_path);
        }
        Ok(())
    }
    pub fn init(mut opts: CompileArgs, tmp_workspace: TempDir) -> Result<Options> {
        Self::check_compile_opts(&mut opts)?;
        Ok(Options {
            compile_opts: opts.clone(),
            tmpdir: tmp_workspace,
        })
    }
}

pub struct EunomiaWorkspace {
    pub options: Options,
}

impl EunomiaWorkspace {
    pub fn init(opts: CompileArgs) -> Result<EunomiaWorkspace> {
        // create workspace
        let tmp_workspace = TempDir::new().unwrap();
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

    #[arg(short, long, default_value_t = ("").to_string(), help = "path of output bpf object")]
    pub output_path: String,

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

    #[arg(short, long, default_value_t = ("").to_string(), help = "additional c flags for clang")]
    pub additional_cflags: String,

    #[arg(short, long, default_value_t = ("clang").to_string(), help = "path of clang binary")]
    pub clang_bin: String,

    #[arg(short, long, default_value_t = ("llvm-strip").to_string(), help = "path of the llvm-strip binary")]
    pub llvm_strip_bin: String,

    #[arg(
        short,
        long,
        default_value_t = true,
        help = "Generate a `package.json` containing the binary of the ELF file of the ebpf program"
    )]
    pub generate_package_json: bool,
}

/// Get output path for json: output.meta.json
pub fn get_output_config_path(args: &Options) -> String {
    let output_path = if args.compile_opts.output_path.is_empty() {
        path::Path::new(&args.compile_opts.source_path).with_extension("")
    } else {
        path::Path::new(&args.compile_opts.output_path).to_path_buf()
    };
    let output_json_path = if args.compile_opts.yaml {
        output_path.with_extension("skel.yaml")
    } else {
        output_path.with_extension("skel.json")
    };
    output_json_path.to_str().unwrap().to_string()
}

/// Get output path for bpf object: output.bpf.o  
pub fn get_output_object_path(args: &Options) -> String {
    let output_path = if args.compile_opts.output_path.is_empty() {
        path::Path::new(&args.compile_opts.source_path).with_extension("")
    } else {
        path::Path::new(&args.compile_opts.output_path).to_path_buf()
    };
    let output_object_path = output_path.with_extension("bpf.o");
    output_object_path.to_str().unwrap().to_string()
}

pub fn get_object_name(args: &Options) -> String {
    let object_path = &get_output_object_path(args);
    let name = object_path.split('/').last().unwrap();
    name.to_string()
}

pub fn get_output_tar_path(args: &Options) -> String {
    let output_path = if args.compile_opts.output_path.is_empty() {
        path::Path::new(&args.compile_opts.source_path).with_extension("")
    } else {
        path::Path::new(&args.compile_opts.output_path).to_path_buf()
    };
    let output_object_path = output_path.with_extension("tar");
    output_object_path.to_str().unwrap().to_string()
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
    let bpftool_path = get_bpftool_path(&args.tmpdir).unwrap();

    let btf_archive_path = Path::new(&args.compile_opts.btfhub_archive);
    let btf_tmp = args.tmpdir.path();

    let custom_archive_path = Path::new(&args.compile_opts.output_path).join("custom-archive");
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
        bpftool_path,
        get_output_object_path(args),
        custom_archive_path.to_string_lossy(),
        btf_tmp.to_string_lossy(),
        custom_archive_path.to_string_lossy()
    );

    let output = handle_runscrpt_with_log!(command, "Failed to generate tailored btf files");

    Ok(output)
}

pub fn package_btfhub_tar(args: &Options) -> Result<()> {
    let tar = &get_output_tar_path(args);
    let tar_path = Path::new(tar);
    let btf_path = Path::new(&args.compile_opts.output_path).join("custom-archive");
    let package = fs::File::create(tar_path).unwrap();

    let mut tar = Builder::new(package);
    let mut object = fs::File::open(get_output_object_path(args)).unwrap();
    let mut json = fs::File::open(get_output_package_config_path(args)).unwrap();

    tar.append_dir_all(".", btf_path).unwrap();
    tar.append_file("package.json", &mut json).unwrap();
    tar.append_file(&get_object_name(args), &mut object)
        .unwrap();
    tar.finish().unwrap();
    Ok(())
}

pub fn get_source_file_temp_path(args: &Options) -> String {
    let source_path = path::Path::new(&args.compile_opts.source_path);
    let source_file_temp_path = source_path.with_extension("temp.c");
    source_file_temp_path.to_str().unwrap().to_string()
}

/// Get include paths from clang
pub fn get_bpf_sys_include(args: &CompileArgs) -> Result<String> {
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
        .collect())
}

/// Get target arch: x86 or arm, etc
pub fn get_target_arch() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "powerpc64" => "powerpc",
        "mips64" => "mips",
        "riscv64" => "riscv",
        arch => arch,
    };

    debug!("Target architecture: {arch}");

    arch.to_string()
}

/// Get eunomia home include dirs
pub fn get_eunomia_include(args: &Options) -> Result<String> {
    let eunomia_tmp_workspace = args.tmpdir.path();
    let eunomia_include = path::Path::new(&eunomia_tmp_workspace);
    let eunomia_include = match eunomia_include.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            return Err(anyhow::anyhow!(
                e.to_string() + ": failed to find eunomia workspace"
            ))
        }
    };
    let eunomia_include = eunomia_include.join("include");
    let vmlinux_include = eunomia_include.join("vmlinux");
    let vmlinux_include = vmlinux_include.join(get_target_arch());
    Ok(format!(
        "-I{} -I{}",
        eunomia_include.to_str().unwrap(),
        vmlinux_include.to_str().unwrap()
    ))
}

/// Get eunomia bpftool path
pub fn get_bpftool_path(tmp_workspace: &TempDir) -> Result<String> {
    let eunomia_tmp_workspace = tmp_workspace.path();
    let eunomia_bin = path::Path::new(&eunomia_tmp_workspace).join("bin");
    let bpftool = eunomia_bin.join("bpftool");
    let bpftool = match bpftool.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            return Err(anyhow::anyhow!(
                e.to_string() + ": failed to find bpftool binary"
            ))
        }
    };
    let f = std::fs::File::open(&bpftool)?;
    let metadata = f.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o744);
    std::fs::set_permissions(&bpftool, permissions)?;
    Ok(bpftool.to_str().unwrap().to_string())
}

/// Get base dir of source path as include args
pub fn get_base_dir_include(source_path: &str) -> Result<String> {
    // add base dir as include path
    let base_dir = path::Path::new(source_path).parent().unwrap();
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
    Ok(format!("-I{}", base_dir.to_str().unwrap()))
}

pub fn get_output_package_config_path(args: &Options) -> String {
    let output_json_path = get_output_config_path(args);
    let output_package_config_path = Path::new(&output_json_path)
        .parent()
        .unwrap()
        .join("package.json");
    output_package_config_path.to_str().unwrap().to_string()
}

pub fn get_wasm_header_path(args: &Options) -> String {
    let output_json_path = get_output_config_path(args);
    let output_wasm_header_path = Path::new(&output_json_path)
        .parent()
        .unwrap()
        .join("ewasm-skel.h");
    output_wasm_header_path.to_str().unwrap().to_string()
}

/// embed workspace
#[derive(RustEmbed)]
#[folder = "$OUT_DIR/workspace/"]
struct Workspace;

pub fn init_eunomia_workspace(tmp_workspace: &TempDir) -> Result<()> {
    let eunomia_tmp_workspace = tmp_workspace.path();

    for file in Workspace::iter() {
        let file_path = format!(
            "{}/{}",
            eunomia_tmp_workspace.to_string_lossy(),
            file.as_ref()
        );
        let file_dir = Path::new(&file_path).parent().unwrap();
        if !file_dir.exists() {
            std::fs::create_dir_all(file_dir)?;
        }
        let content = Workspace::get(file.as_ref()).unwrap();
        std::fs::write(&file_path, content.data.as_ref())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests;
