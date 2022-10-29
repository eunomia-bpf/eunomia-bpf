use std::path;

use anyhow::Result;
use clap::Parser;

/// The eunomia-bpf compile tool
#[derive(Parser, Debug, Default, Clone)]
#[command(
    author,
    version,
    about = "eunomia compiler",
    long_about = "see https://github.com/eunomia-bpf/eunomia-bpf for more information"
)]
pub struct Args {
    /// path of the bpf.c file to compile
    #[arg()]
    pub source_path: String,

    /// path of the bpf.h header for defining event struct
    #[arg()]
    pub export_event_header: String,

    /// path of output bpf object
    #[arg(short, long, default_value_t = ("").to_string())]
    pub output_path: String,

    /// include path of compile btf object
    #[arg(short, long, default_value_t = ("").to_string())]
    pub include_path: String,

    /// path of clang binary
    #[arg(short, long, default_value_t = ("clang").to_string())]
    pub clang_bin: String,

    /// path of llvm strip binary
    #[arg(short, long, default_value_t = ("llvm-strip").to_string())]
    pub llvm_strip_bin: String,

    /// pack bpf object in JSON format with zlib compression and base64 encoding
    #[arg(short, long, default_value_t = false)]
    pub pack_object: bool,
}

/// Get home directory from env
pub fn get_eunomia_home() -> Result<String> {
    let eunomia_home = std::env::var("EUNOMIA_HOME");
    match eunomia_home {
        Ok(home) => Ok(home),
        Err(_) => match home::home_dir() {
            Some(home) => {
                let home = home.join(".eunomia");
                Ok(home.to_str().unwrap().to_string())
            }
            None => return Err(anyhow::anyhow!("HOME is not found")),
        },
    }
}

/// Get output path for json: output.meta.json
pub fn get_output_json_path(args: &Args) -> String {
    let output_path = if args.output_path == "" {
        path::Path::new(&args.source_path).with_extension("")
    } else {
        path::Path::new(&args.output_path).to_path_buf()
    };
    let output_json_path = output_path.with_extension("skel.json");
    output_json_path.to_str().unwrap().to_string()
}

/// Get output path for bpf object: output.bpf.o  
pub fn get_output_object_path(args: &Args) -> String {
    let output_path = if args.output_path == "" {
        path::Path::new(&args.source_path).with_extension("")
    } else {
        path::Path::new(&args.output_path).to_path_buf()
    };
    let output_object_path = output_path.with_extension("bpf.o");
    output_object_path.to_str().unwrap().to_string()
}

pub const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";
pub const EXPORT_DEFINE_C_FILE: &str = "export_events_define.bpf.c";
pub const EXPORT_DEFINE_BPF_OBJECT: &str = "export_events_define.bpf.o";
