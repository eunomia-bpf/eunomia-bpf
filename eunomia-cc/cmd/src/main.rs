mod compile_bpf;
mod config;
mod document_parser;
mod export_types;

use crate::config::get_eunomia_home;
use anyhow::Result;
use clap::Parser;
use compile_bpf::*;
use config::Args;
use rust_embed::RustEmbed;
use std::path::Path;

/// embed workspace
#[derive(RustEmbed)]
#[folder = "../workspace/"]
struct Workspace;

fn main() -> Result<()> {
    let args = Args::parse();
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
    compile_bpf(&args)?;
    if !args.subskeleton {
        pack_object_in_config(&args)?;
    }
    Ok(())
}
