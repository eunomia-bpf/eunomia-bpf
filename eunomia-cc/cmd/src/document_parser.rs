extern crate clang;
use std::path::Path;

use crate::config::*;
use anyhow::Result;
use clang::*;
use serde_json::{json, Value};

pub fn parse_source_documents(args: &Args, source_path: &str) -> Result<Value> {
    let bpf_sys_include = get_bpf_sys_include(args)?;
    let target_arch = get_target_arch(args)?;
    let target_arch = String::from("-D__TARGET_ARCH_") + &target_arch;
    let eunomia_include = get_eunomia_include(args)?;
    let base_dir_include = get_base_dir_include(source_path)?;
    let mut compile_args = vec!["-g", "-O2", "-target bpf", &target_arch];
    compile_args.append(&mut bpf_sys_include.split(' ').collect::<Vec<&str>>());
    compile_args.append(&mut eunomia_include.split(' ').collect::<Vec<&str>>());
    compile_args.push(&base_dir_include);
    compile_args.append(&mut args.additional_cflags.split(' ').collect::<Vec<&str>>());

    // Acquire an instance of `Clang`
    let clang = Clang::new().unwrap();
    // Create a new `Index`
    let index = Index::new(&clang, false, true);
    // Parse a source file into a translation unit
    let tu = index
        .parser(source_path)
        .arguments(&compile_args)
        .parse()
        .unwrap();

    let _source_path = Path::new(source_path);
    let canonic_source_path = _source_path.canonicalize().unwrap();

    // Get the structs in this translation unit
    let structs = tu
        .get_entity()
        .get_children()
        .into_iter()
        .filter(|e| {
            e.get_location()
                .unwrap()
                .get_file_location()
                .file
                .unwrap()
                .get_path()
                == canonic_source_path
        })
        .collect::<Vec<_>>();

    // Print information about the structs
    for e in structs {
        println!("struct: {:?}", e);
        println!("definition: {:?}", e.get_definition());
        println!("parse comm: {:?}", e.get_parsed_comment());
        println!("");
    }
    Ok(json!({}))
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parse_struct() {
        let args = Args {
            ..Default::default()
        };
        let source_path = "/home/yunwei/eunomia-bpf/eunomia-cc/cmd/test/client.bpf.c";
        parse_source_documents(&args, source_path).unwrap();
    }
}
