use clap::Parser;
use anyhow::Result;

/// The eunomia-bpf compile tool
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "eunomia compiler",
    long_about = "see https://github.com/eunomia-bpf/eunomia-bpf for more information"
)]

pub struct Args {
    /// path of the bpf.c file to compile
    #[arg(short, long)]
    pub source_path: String,

    /// path of output bpf object
    #[arg(short, long, default_value_t = ("output.bpf.o").to_string())]
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
}

/// Get home directory from env
pub fn get_eunomia_home() -> Result<String> {
    let eunomia_home = std::env::var("EUNOMIA_HOME");
    match eunomia_home {
        Ok(home) => Ok(home),
        Err(_) => {
            match home::home_dir() {
                Some(home) => {
                    let home = home.join(".eunomia");
                    Ok(home.to_str().unwrap().to_string())
                },
                None => return Err(anyhow::anyhow!("HOME is not found")),
            }
        },
    }
}