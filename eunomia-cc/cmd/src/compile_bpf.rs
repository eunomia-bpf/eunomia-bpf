use crate::{config::*, export_types::*};
use anyhow::Result;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_json::{json, Value};
use std::io::prelude::*;
use std::{
    fs,
    path::{self, Path},
};

/// Get include paths from clang
fn get_bpf_sys_include(args: &Args) -> Result<String> {
    let mut command = format!("{}", args.clang_bin);
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
fn get_target_arch(args: &Args) -> Result<String> {
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
fn get_eunomia_include(args: &Args) -> Result<String> {
    let eunomia_home = get_eunomia_home()?;
    let eunomia_include = path::Path::new(&eunomia_home);
    let eunomia_include = fs::canonicalize(eunomia_include)?;
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
fn get_bpftool_path() -> Result<String> {
    let eunomia_home = get_eunomia_home()?;
    let eunomia_bin = path::Path::new(&eunomia_home).join("bin");
    let bpftool = eunomia_bin.join("bpftool");
    let bpftool = fs::canonicalize(bpftool)?;
    Ok(bpftool.to_str().unwrap().to_string())
}

/// compile bpf object
fn compile_bpf_object(args: &Args, source_path: &str, output_path: &str) -> Result<()> {
    let bpf_sys_include = get_bpf_sys_include(args)?;
    let target_arch = get_target_arch(args)?;
    // add base dir as include path
    let base_dir = path::Path::new(source_path).parent().unwrap();
    let base_dir = if base_dir == path::Path::new("") {
        path::Path::new("./")
    } else {
        base_dir
    };
    let base_dir = fs::canonicalize(base_dir)?;
    let base_include = format!("-I{}", base_dir.to_str().unwrap());
    let command = format!(
        "{} -g -O2 -target bpf -D__TARGET_ARCH_{} {} {} {} {} -c {} -o {}",
        args.clang_bin,
        target_arch,
        bpf_sys_include,
        get_eunomia_include(args)?,
        args.additional_cflags,
        base_include,
        source_path,
        output_path
    );
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to compile bpf object"));
    }
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }
    let command = format!("{} -g {}", args.llvm_strip_bin, output_path);
    let (code, _output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("llvm-strip failed"));
    }
    Ok(())
}

/// get the skel as json object
fn get_bpf_skel_json(object_path: &String, args: &Args) -> Result<String> {
    let bpftool_bin = get_bpftool_path()?;
    let command = format!("{} gen skeleton {} -j", bpftool_bin, object_path);
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get bpf skel json"));
    }
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }
    Ok(output)
}

fn _link_bpf_object_with_export(
    args: &Args,
    tmp_dir: &Path,
    output_bpf_object_path: &String,
) -> Result<()> {
    const EXPORT_DEFINE_BPF_OBJECT: &str = "export_events_define.bpf.o";
    // compile export c file
    let export_object_path = tmp_dir.join(EXPORT_DEFINE_BPF_OBJECT);
    let temp_path = output_bpf_object_path.to_owned() + ".temp";

    let bpftool_bin = get_bpftool_path()?;
    let command = format!(
        "{} gen object {} {} {}",
        bpftool_bin,
        temp_path,
        export_object_path.to_str().unwrap(),
        output_bpf_object_path,
    );
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get export types json"));
    }
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }
    fs::copy(&temp_path, output_bpf_object_path)?;
    fs::remove_file(temp_path)?;
    Ok(())
}

/// get the export typs as json object
fn get_export_types_json(args: &Args, output_bpf_object_path: &String) -> Result<String> {
    let bpftool_bin = get_bpftool_path()?;
    let command = format!(
        "{} btf dump file {} format c -j",
        bpftool_bin, output_bpf_object_path
    );
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get export types json"));
    }
    // fiter the output to get the export types json
    let export_structs = find_all_export_structs(args)?;
    let export_types_json: Value = serde_json::from_str(&output).unwrap();
    let export_types_json = export_types_json["structs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| {
            let name = x["name"].as_str().unwrap();
            export_structs.contains(&name.to_string())
        })
        .map(|x| x.to_owned())
        .collect::<Vec<Value>>();
    if args.verbose {
        println!("$ {}\n{}", command, output);
    }
    Ok(serde_json::to_string(&export_types_json).unwrap())
}

/// do actual work for compiling
fn do_compile(args: &Args, temp_source_file: &str) -> Result<()> {
    let output_bpf_object_path = get_output_object_path(args);
    let output_json_path = get_output_config_path(args);
    let mut meta_json = json!({});

    // compile bpf object
    println!("Compiling bpf object...");
    compile_bpf_object(args, temp_source_file, &output_bpf_object_path)?;
    let bpf_skel_json = get_bpf_skel_json(&output_bpf_object_path, args)?;
    let bpf_skel_json = serde_json::from_str(&bpf_skel_json)?;
    meta_json["bpf_skel"] = bpf_skel_json;

    // compile export types
    if args.export_event_header != "" {
        println!("Generating export types...");
        let export_types_json = get_export_types_json(args, &output_bpf_object_path)?;
        let export_types_json: Value = serde_json::from_str(&export_types_json)?;
        meta_json["export_types"] = export_types_json;
    }

    let meta_config_str = if args.yaml {
        serde_yaml::to_string(&meta_json)?
    } else {
        serde_json::to_string(&meta_json)?
    };
    fs::write(output_json_path, meta_config_str)?;
    Ok(())
}

/// compile JSON file
pub fn compile_bpf(args: &Args) -> Result<()> {
    // backup old files
    let source_file_content = fs::read_to_string(&args.source_path)?;
    let temp_source_file = get_source_file_temp_path(args);

    if args.export_event_header != "" {
        // create temp source file
        fs::write(&temp_source_file, source_file_content)?;
        add_unused_ptr_for_structs(args, &temp_source_file)?;
    }
    let res = do_compile(args, &temp_source_file);
    if args.export_event_header != "" {
        fs::remove_file(temp_source_file)?;
    }
    res
}

/// pack the object file into a package.json
pub fn pack_object_in_config(args: &Args) -> Result<()> {
    let output_bpf_object_path = get_output_object_path(args);
    let bpf_object = fs::read(output_bpf_object_path)?;

    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(&bpf_object)?;
    let compressed_bytes = e.finish().unwrap();
    let encode_bpf_object = base64::encode(&compressed_bytes);
    let output_json_path = get_output_config_path(args);
    let meta_json_str = fs::read_to_string(&output_json_path).unwrap();
    let meta_json: Value = if let Ok(json) = serde_json::from_str(&meta_json_str) {
        json
    } else {
        serde_yaml::from_str(&meta_json_str).unwrap()
    };
    let package_config = json!({
        "bpf_object": encode_bpf_object,
        "bpf_object_size": bpf_object.len(),
        "meta": meta_json,
    });
    println!(
        "Packing oebpf object and config into {}...",
        output_json_path
    );
    if args.yaml {
        let output_package_config_path = Path::new(&output_json_path)
            .parent()
            .unwrap()
            .join("package.yaml");
        let package_config_str = serde_yaml::to_string(&package_config).unwrap();
        fs::write(output_package_config_path, package_config_str)?;
    } else {
        let output_package_config_path = Path::new(&output_json_path)
            .parent()
            .unwrap()
            .join("package.json");
        let package_config_str = serde_json::to_string(&package_config).unwrap();
        fs::write(output_package_config_path, package_config_str)?;
    };
    Ok(())
}

#[cfg(test)]
mod test {
    const TEMP_EUNOMIA_DIR: &str = "/tmp/eunomia";
    use super::*;

    #[test]
    fn test_get_attr() {
        let args = Args {
            source_path: "".to_string(),
            clang_bin: "clang".to_string(),
            llvm_strip_bin: "llvm-strip".to_string(),
            output_path: "".to_string(),
            additional_cflags: "".to_string(),
            export_event_header: "".to_string(),
            pack_object: false,
            verbose: false,
            yaml: false,
        };
        let sys_include = get_bpf_sys_include(&args).unwrap();
        println!("{}", sys_include);
        let target_arch = get_target_arch(&args).unwrap();
        println!("{}", target_arch);
        let eunomia_include = get_eunomia_include(&args).unwrap();
        println!("{}", eunomia_include);
    }

    #[test]
    fn test_compile_bpf() {
        let test_bpf = include_str!("../test/client.bpf.c");
        let test_event = include_str!("../test/event.h");
        let tmp_dir = path::Path::new(TEMP_EUNOMIA_DIR);
        let tmp_dir = tmp_dir.join("test_compile_bpf");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(
            tmp_dir.join("other_header.h"),
            include_str!("../test/other_header.h"),
        )
        .unwrap();
        let source_path = tmp_dir.join("client.bpf.c");
        println!("source_path: {}", source_path.to_str().unwrap());
        fs::write(&source_path, test_bpf).unwrap();
        let event_path = tmp_dir.join("event.h");
        fs::write(&event_path, test_event).unwrap();
        let args = Args {
            source_path: source_path.to_str().unwrap().to_string(),
            clang_bin: "clang".to_string(),
            llvm_strip_bin: "llvm-strip".to_string(),
            output_path: "/tmp/eunomia/test".to_string(),
            additional_cflags: "".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
            pack_object: false,
            verbose: false,
            yaml: false,
        };
        compile_bpf(&args).unwrap();
        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_export_multi_and_pack() {
        let test_bpf = include_str!("../test/client.bpf.c");
        let test_event = include_str!("../test/multi_event.h");
        let tmp_dir = path::Path::new(TEMP_EUNOMIA_DIR);
        let tmp_dir = tmp_dir.join("test_export_multi_and_pack");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::write(
            tmp_dir.join("other_header.h"),
            include_str!("../test/other_header.h"),
        )
        .unwrap();
        let source_path = tmp_dir.join("export_multi_struct.bpf.c");
        fs::write(&source_path, test_bpf).unwrap();
        let event_path = tmp_dir.join("event.h");
        fs::write(&event_path, test_event).unwrap();
        let args = Args {
            source_path: source_path.to_str().unwrap().to_string(),
            clang_bin: "clang".to_string(),
            llvm_strip_bin: "llvm-strip".to_string(),
            output_path: "/tmp/eunomia/export_multi_struct_test".to_string(),
            additional_cflags: "".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
            pack_object: false,
            verbose: false,
            yaml: false,
        };
        compile_bpf(&args).unwrap();
        pack_object_in_config(&args).unwrap();
        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_compress_and_pack() {
        let bpf_object = "hello world hello world hello world".as_bytes();
        let encode_bpf_object = base64::encode(&bpf_object);
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&bpf_object).unwrap();
        let compressed_bytes = e.finish().unwrap();
        let encode_bpf_object = base64::encode(&compressed_bytes);
    }
}
