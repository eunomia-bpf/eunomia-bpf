use std::{fs, path};

use anyhow::Result;
use clap::Parser;
use rust_embed::RustEmbed;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

    /// print the command execution
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// output config skel file in yaml
    #[arg(short, long, default_value_t = false)]
    pub yaml: bool,
}

static EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";
static FHS_EUNOMIA_HOME_ENTRY: &str = "/usr/share/eunomia";

/// Get home directory from env
pub fn get_eunomia_home() -> Result<String> {
    let eunomia_home = std::env::var(EUNOMIA_HOME_ENV);
    match eunomia_home {
        Ok(home) => Ok(home),
        Err(_) => match home::home_dir() {
            Some(home) => {
                let home = home.join(".eunomia");
                Ok(home.to_str().unwrap().to_string())
            }
            None => {
                if path::Path::new(FHS_EUNOMIA_HOME_ENTRY).exists() {
                    Ok(FHS_EUNOMIA_HOME_ENTRY.to_string())
                } else {
                    Err(anyhow::anyhow!("HOME is not found"))
                }
            }
        },
    }
}

/// Get output path for json: output.meta.json
pub fn get_output_config_path(args: &CompileOptions) -> String {
    let output_path = if args.output_path.is_empty() {
        path::Path::new(&args.source_path).with_extension("")
    } else {
        path::Path::new(&args.output_path).to_path_buf()
    };
    let output_json_path = if args.yaml {
        output_path.with_extension("skel.yaml")
    } else {
        output_path.with_extension("skel.json")
    };
    output_json_path.to_str().unwrap().to_string()
}

/// Get output path for bpf object: output.bpf.o  
pub fn get_output_object_path(args: &CompileOptions) -> String {
    let output_path = if args.output_path.is_empty() {
        path::Path::new(&args.source_path).with_extension("")
    } else {
        path::Path::new(&args.output_path).to_path_buf()
    };
    let output_object_path = output_path.with_extension("bpf.o");
    output_object_path.to_str().unwrap().to_string()
}

pub fn get_source_file_temp_path(args: &CompileOptions) -> String {
    let source_path = path::Path::new(&args.source_path);
    let source_file_temp_path = source_path.with_extension("temp.c");
    source_file_temp_path.to_str().unwrap().to_string()
}

/// Get include paths from clang
pub fn get_bpf_sys_include(args: &CompileOptions) -> Result<String> {
    let mut command = args.clang_bin.clone();
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
    Ok(output.replace("\n", " "))
}

/// Get target arch: x86 or arm, etc
pub fn get_target_arch(args: &CompileOptions) -> Result<String> {
    let command = r#" uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/'
     "#;
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get target arch"));
    }
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }
    Ok(output.replace("\n", ""))
}

/// Get eunomia home include dirs
pub fn get_eunomia_include(args: &CompileOptions) -> Result<String> {
    let eunomia_home = get_eunomia_home()?;
    let eunomia_include = path::Path::new(&eunomia_home);
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
    let vmlinux_include = vmlinux_include.join(get_target_arch(args)?);
    Ok(format!(
        "-I{} -I{}",
        eunomia_include.to_str().unwrap(),
        vmlinux_include.to_str().unwrap()
    ))
}

/// Get eunomia bpftool path
pub fn get_bpftool_path() -> Result<String> {
    let eunomia_home = get_eunomia_home()?;
    let eunomia_bin = path::Path::new(&eunomia_home).join("bin");
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

/// embed workspace
#[derive(RustEmbed)]
#[folder = "../workspace/"]
struct Workspace;

pub fn create_eunomia_home() -> Result<()> {
    let eunomia_home_path = get_eunomia_home()?;
    if !Path::new(&eunomia_home_path).exists() {
        std::fs::create_dir_all(&eunomia_home_path)?;
        println!("creating eunomia home dir: {}", eunomia_home_path);
        for file in Workspace::iter() {
            let file_path = format!("{}/{}", eunomia_home_path, file.as_ref());
            let file_dir = Path::new(&file_path).parent().unwrap();
            if !file_dir.exists() {
                std::fs::create_dir_all(file_dir)?;
            }
            let content = Workspace::get(file.as_ref()).unwrap();
            std::fs::write(&file_path, content.data.as_ref())?;
            println!("creating file: {}", file_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_args() {
        let _ = CompileOptions::parse_from(&["ecc", "test.c"]);
        let _ = CompileOptions::parse_from(&["ecc", "test.c", "-o", "test.o"]);
        let _ = CompileOptions::parse_from(&["ecc", "test.c", "test.h", "-v"]);
        let _ = CompileOptions::parse_from(&["ecc", "test.c", "test.h", "-y"]);
        let _ = CompileOptions::parse_from(&["ecc", "test.c", "-c", "clang"]);
        let _ = CompileOptions::parse_from(&["ecc", "test.c", "-l", "llvm-strip"]);
    }

    #[test]
    fn test_get_base_dir_include_fail() {
        let source_path = "/xxx/test.c";
        let _ = get_base_dir_include(source_path).unwrap_err();
    }

    #[test]
    fn test_get_eunomia_home() {
        let eunomia_home_from_env = std::env::var(EUNOMIA_HOME_ENV);
        let eunomia_home_from_home = home::home_dir().unwrap();

        match eunomia_home_from_env {
            Ok(path) => assert_eq!(get_eunomia_home().unwrap(), path),
            Err(_) => {
                if get_eunomia_home().is_err() {
                    assert!(true)
                }

                if eunomia_home_from_home.exists() {
                    assert_eq!(
                        get_eunomia_home().unwrap(),
                        eunomia_home_from_home
                            .join(".eunomia")
                            .into_os_string()
                            .into_string()
                            .unwrap()
                    );
                } else {
                    assert_eq!(
                        get_eunomia_home().unwrap(),
                        FHS_EUNOMIA_HOME_ENTRY.to_string()
                    )
                }
            }
        }
    }

    #[test]
    fn test_create_eunomia_home() {
        create_eunomia_home().unwrap();
        let home = get_eunomia_home().unwrap();
        assert!(Path::new(&home).exists());
    }
}
