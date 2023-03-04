//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{fs, path};

use anyhow::Result;
use clap::Parser;
use eunomia_rs::{copy_dir_all, TempDir};
use rust_embed::RustEmbed;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct Options {
    pub tmpdir: TempDir,
    pub compile_opts: CompileOptions,
}

impl Options {
    fn check_compile_opts(opts: &mut CompileOptions) -> Result<()> {
        if opts.header_only {
            // treat header as a source file
            opts.export_event_header.clone_from(&opts.source_path);
        }
        Ok(())
    }
    pub fn init(mut opts: CompileOptions, tmp_workspace: TempDir) -> Result<Options> {
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
    pub fn init(opts: CompileOptions) -> Result<EunomiaWorkspace> {
        // create workspace
        let tmp_workspace = TempDir::new().unwrap();
        if let Some(ref p) = opts.parameters.workspace_path {
            let src = Path::new(p);
            copy_dir_all(src, tmp_workspace.path())?;
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
pub struct CompileOptions {
    /// path of the bpf.c file to compile
    #[arg()]
    pub source_path: String,

    /// path of the bpf.h header for defining event struct
    #[arg(default_value_t = ("").to_string())]
    pub export_event_header: String,

    /// path of output bpf object
    #[arg(short, long, default_value_t = ("").to_string())]
    pub output_path: String,

    /// parameters related to compilation
    #[clap(flatten)]
    pub parameters: CompileParams,

    /// print the command execution
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// output config skel file in yaml
    #[arg(short, long, default_value_t = false)]
    pub yaml: bool,

    /// generate a bpf object for struct definition
    /// in header file only
    #[arg(long, default_value_t = false)]
    pub header_only: bool,

    /// generate wasm include header
    #[arg(long, default_value_t = false)]
    pub wasm_header: bool,
}

#[derive(Parser, Debug, Default, Clone)]
pub struct CompileParams {
    /// custom workspace path
    #[arg(short, long)]
    pub workspace_path: Option<String>,

    /// additional c flags for clang
    #[arg(short, long, default_value_t = ("").to_string())]
    pub additional_cflags: String,

    /// path of clang binary
    #[arg(short, long, default_value_t = ("clang").to_string())]
    pub clang_bin: String,

    /// path of llvm strip binary
    #[arg(short, long, default_value_t = ("llvm-strip").to_string())]
    pub llvm_strip_bin: String,

    /// do not pack bpf object in config file
    #[arg(short, long, default_value_t = false)]
    pub subskeleton: bool,
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

pub fn get_source_file_temp_path(args: &Options) -> String {
    let source_path = path::Path::new(&args.compile_opts.source_path);
    let source_file_temp_path = source_path.with_extension("temp.c");
    source_file_temp_path.to_str().unwrap().to_string()
}

/// Get include paths from clang
pub fn get_bpf_sys_include(args: &CompileOptions) -> Result<String> {
    let mut command = args.parameters.clang_bin.clone();
    command += r#" -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'
     "#;
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get bpf sys include"));
    }
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }

    Ok(output
        .chars()
        .map(|x| match x {
            '\n' => ' ',
            _ => x,
        })
        .collect())
}

/// Get target arch: x86 or arm, etc
pub fn get_target_arch(args: &CompileOptions) -> Result<String> {
    let command = r#" uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' \
                               | sed 's/mips.*/mips/' | sed 's/riscv64/riscv/'
     "#;
    let (code, mut output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get target arch"));
    }
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }
    output.retain(|x| x != '\n');
    Ok(output)
}

/// Get eunomia home include dirs
pub fn get_eunomia_include(args: &Options) -> Result<String> {
    let eunomia_tmp_workspace = args.tmpdir.path();
    let eunomia_include = path::Path::new(&eunomia_tmp_workspace);
    let eunomia_include = match eunomia_include.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            return Err(anyhow::anyhow!(
                e.to_string() + ": failed to find eunomia home"
            ))
        }
    };
    let eunomia_include = eunomia_include.join("include");
    let vmlinux_include = eunomia_include.join("vmlinux");
    let vmlinux_include = vmlinux_include.join(get_target_arch(&args.compile_opts)?);
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
            println!("cannot find compile dir: {}", e);
            return Err(anyhow::anyhow!(e.to_string()));
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
#[folder = "../workspace/"]
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
mod test {
    use super::*;
    use clap::Parser;

    fn init_options(copt: CompileOptions) {
        let mut opts = Options::init(copt, TempDir::new().unwrap()).unwrap();
        opts.compile_opts.parameters.subskeleton = true;
    }

    #[test]
    fn test_parse_args() {
        init_options(CompileOptions::parse_from(&["ecc", "../test/client.bpf.c"]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "-o",
            "test.o",
        ]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "test.h",
            "-v",
        ]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "test.h",
            "-y",
        ]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "-c",
            "clang",
        ]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "-l",
            "llvm-strip",
        ]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "--header-only",
        ]));
        init_options(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "-w",
            "/tmp/test",
        ]));
    }

    #[test]
    fn test_get_base_dir_include_fail() {
        let source_path = "/xxx/test.c";
        let _ = get_base_dir_include(source_path).unwrap_err();
    }

    #[test]
    fn test_init_eunomia_workspace() {
        let tmp_workspace = TempDir::new().unwrap();
        init_eunomia_workspace(&tmp_workspace).unwrap();
        // check if workspace and file successfully created
        let bpftool_path = tmp_workspace.path().join("bin/bpftool");
        assert!(bpftool_path.exists());
        let _ = fs::create_dir_all("/tmp/test_workspace");
        // test specifiy workspace
        let _w1 = EunomiaWorkspace::init(CompileOptions::parse_from(&[
            "ecc",
            "../test/client.bpf.c",
            "-w",
            "/tmp/test_workspace",
        ]))
        .unwrap();

        // test default workspace
        let _w2 =
            EunomiaWorkspace::init(CompileOptions::parse_from(&["ecc", "../test/client.bpf.c"]))
                .unwrap();
    }
}
