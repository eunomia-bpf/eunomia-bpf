use std::{os, path, fs};

use crate::config::*;
use anyhow::Result;

/// Get include paths from clang
fn get_bpf_sys_include(args: &Args) -> Result<String> {
    let mut command = format!("{}", args.clang_bin);
    command += r#" -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'
     "#;
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("{}", error);
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
        println!("{}", command);
        println!("{}", error);
        return Err(anyhow::anyhow!("failed to get target arch"));
    }
    Ok(output.replace("\n", ""))
}

fn get_eunomia_include() -> Result<String> {
    let eunomia_include = get_eunomia_home()?;
    let eunomia_include = path::Path::new(&eunomia_include);
    let eunomia_include = fs::canonicalize(eunomia_include)?;
    let eunomia_include = eunomia_include.join("include");
    let vmlinux_include = eunomia_include.join("vmlinux");
    let vmlinux_include = vmlinux_include.join(get_target_arch()?);
    Ok(format!("-I{} -I{}", eunomia_include.to_str().unwrap(), vmlinux_include.to_str().unwrap()))
}

pub fn compile_bpf_object(args: &Args, source_path: &String, output_path: &String) -> Result<()> {
    let bpf_sys_include = get_bpf_sys_include(args)?;
    let target_arch = get_target_arch()?;
    let command = format!(
        "{} -g -O2 -target bpf -D__TARGET_ARCH_{} {} {} {} -c {} -o {}",
        args.clang_bin,
        target_arch,
        bpf_sys_include,
        get_eunomia_include()?,
        args.include_path,
        source_path,
        output_path
    );
    let (code, output, error) = run_script::run_script!(command).unwrap();
    if code != 0 {
        println!("{}", command);
        println!("{}", error);
        return Err(anyhow::anyhow!("failed to compile bpf object"));
    }
    println!("{}", output);
    Ok(())
}

pub fn compile_bpf(args: &Args) -> Result<()> {
    compile_bpf_object(args, &args.source_path, &args.output_path)
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
        };
        let sys_include = get_bpf_sys_include(&args).unwrap();
        println!("{}", sys_include);
        let target_arch = get_target_arch().unwrap();
        println!("{}", target_arch);
        let eunomia_include = get_eunomia_include().unwrap();
        println!("{}", eunomia_include);
    }
}
