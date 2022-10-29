use crate::{config::*, export_types::create_tmp_export_c_file};
use anyhow::Result;
use serde_json::json;
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
    Ok(output.replace("\n", " "))
}

/// Get target arch: x86 or arm, etc
fn get_target_arch() -> Result<String> {
    let command = r#" uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/'
     "#;
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get target arch"));
    }
    Ok(output.replace("\n", ""))
}

/// Get eunomia home include dirs
fn get_eunomia_include() -> Result<String> {
    let eunomia_home = get_eunomia_home()?;
    let eunomia_include = path::Path::new(&eunomia_home);
    let eunomia_include = fs::canonicalize(eunomia_include)?;
    let eunomia_include = eunomia_include.join("include");
    let vmlinux_include = eunomia_include.join("vmlinux");
    let vmlinux_include = vmlinux_include.join(get_target_arch()?);
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
    let target_arch = get_target_arch()?;
    // add base dir as include path
    let base_dir = path::Path::new(source_path).parent().unwrap();
    let base_include = format!("-I{}", base_dir.to_str().unwrap());
    let command = format!(
        "{} -g -O2 -target bpf -D__TARGET_ARCH_{} {} {} {} {} -c {} -o {}",
        args.clang_bin,
        target_arch,
        bpf_sys_include,
        get_eunomia_include()?,
        args.include_path,
        base_include,
        source_path,
        output_path
    );
    let (code, _output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to compile bpf object"));
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
fn get_bpf_skel_json(object_path: &String) -> Result<String> {
    let bpftool_bin = get_bpftool_path()?;
    let command = format!("{} gen skeleton {} -j", bpftool_bin, object_path);
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get bpf skel json"));
    }
    Ok(output)
}

/// get the export typs as json object
fn get_export_types_json(args: &Args) -> Result<String> {
    // create tmp export c file
    let tmp_dir = Path::new(TEMP_EUNOMIA_DIR);
    fs::create_dir_all(tmp_dir).unwrap();
    let temp_file = tmp_dir.join(EXPORT_DEFINE_C_FILE);
    create_tmp_export_c_file(args, temp_file.to_str().unwrap())?;

    // compile export c file
    let export_object_path = tmp_dir.join(EXPORT_DEFINE_BPF_OBJECT);
    compile_bpf_object(
        args,
        temp_file.to_str().unwrap(),
        export_object_path.to_str().unwrap(),
    )?;

    let bpftool_bin = get_bpftool_path()?;
    let command = format!(
        "{} btf dump file {} format c -j",
        bpftool_bin,
        export_object_path.to_str().unwrap()
    );
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("$ {}\n {}", command, error);
        return Err(anyhow::anyhow!("failed to get export types json"));
    }
    Ok(output)
}

/// compile JSON file
pub fn compile_bpf(args: &Args) -> Result<()> {
    let output_bpf_object_path = get_output_object_path(&args.output_path);
    let output_json_path = get_output_json_path(&args.output_path);
    let mut meta_json = json!({});

    compile_bpf_object(args, &args.source_path, &output_bpf_object_path)?;
    let bpf_skel_json = get_bpf_skel_json(&output_bpf_object_path)?;
    let bpf_skel_json = serde_json::from_str(&bpf_skel_json)?;
    meta_json["bpf_skel"] = bpf_skel_json;

    let export_types_json = get_export_types_json(args)?;
    let export_types_json = serde_json::from_str(&export_types_json)?;
    meta_json["export_types"] = export_types_json;

    let meta_json_str = serde_json::to_string(&meta_json)?;
    fs::write(output_json_path, meta_json_str)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_attr() {
        let args = Args {
            source_path: "".to_string(),
            clang_bin: "clang".to_string(),
            llvm_strip_bin: "llvm-strip".to_string(),
            output_path: "".to_string(),
            include_path: "".to_string(),
            export_event_header: "".to_string(),
        };
        let sys_include = get_bpf_sys_include(&args).unwrap();
        println!("{}", sys_include);
        let target_arch = get_target_arch().unwrap();
        println!("{}", target_arch);
        let eunomia_include = get_eunomia_include().unwrap();
        println!("{}", eunomia_include);
    }

    #[test]
    fn test_compile_bpf() {
        let test_bpf = include_str!("../test/client.bpf.c");
        let test_event = include_str!("../test/event.h");
        let tmp_dir = path::Path::new(TEMP_EUNOMIA_DIR);
        fs::write(
            tmp_dir.join("other_header.h"),
            include_str!("../test/other_header.h"),
        )
        .unwrap();
        fs::create_dir_all(tmp_dir).unwrap();
        let source_path = tmp_dir.join("client.bpf.c");
        fs::write(&source_path, test_bpf).unwrap();
        let event_path = tmp_dir.join("event.h");
        fs::write(&event_path, test_event).unwrap();
        let args = Args {
            source_path: source_path.to_str().unwrap().to_string(),
            clang_bin: "clang".to_string(),
            llvm_strip_bin: "llvm-strip".to_string(),
            output_path: "/tmp/eunomia/test".to_string(),
            include_path: "".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
        };
        compile_bpf(&args).unwrap();
    }

    #[test]
    fn test_compile_export_multi_struct() {
        let test_bpf = include_str!("../test/client.bpf.c");
        let test_event = include_str!("../test/multi_event.h");
        let tmp_dir = path::Path::new(TEMP_EUNOMIA_DIR);
        fs::write(
            tmp_dir.join("other_header.h"),
            include_str!("../test/other_header.h"),
        )
        .unwrap();
        fs::create_dir_all(tmp_dir).unwrap();
        let source_path = tmp_dir.join("export_multi_struct.bpf.c");
        fs::write(&source_path, test_bpf).unwrap();
        let event_path = tmp_dir.join("event.h");
        fs::write(&event_path, test_event).unwrap();
        let args = Args {
            source_path: source_path.to_str().unwrap().to_string(),
            clang_bin: "clang".to_string(),
            llvm_strip_bin: "llvm-strip".to_string(),
            output_path: "/tmp/eunomia/export_multi_struct_test".to_string(),
            include_path: "".to_string(),
            export_event_header: event_path.to_str().unwrap().to_string(),
        };
        compile_bpf(&args).unwrap();
    }
}
