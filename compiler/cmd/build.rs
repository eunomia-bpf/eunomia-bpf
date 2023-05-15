use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context};
use fs_extra::dir::CopyOptions;

const DEFAULT_BPFTOOL_REPO: &str = "https://github.com/eunomia-bpf/bpftool";
const DEFAULT_BPFTOOL_REF: &str = "0594034";

const DEFAULT_VMLINUX_REPO: &str = "https://github.com/eunomia-bpf/vmlinux";
const DEFAULT_VMLINUX_REF: &str = "933f83b";

fn workdir() -> PathBuf {
    PathBuf::from(std::env::var("OUT_DIR").unwrap())
}
fn bpftool_repodir() -> PathBuf {
    PathBuf::from("bpftool")
}

fn bpftool_repo() -> String {
    std::env::var("BPFTOOL_REPO").unwrap_or_else(|_| DEFAULT_BPFTOOL_REPO.to_string())
}

fn bpftool_ref() -> String {
    std::env::var("BPFTOOL_HASH").unwrap_or_else(|_| DEFAULT_BPFTOOL_REF.to_string())
}

fn vmlinux_repodir() -> PathBuf {
    PathBuf::from("vmlinux")
}

fn vmlinux_repo() -> String {
    std::env::var("VMLINUX_REPO").unwrap_or_else(|_| DEFAULT_VMLINUX_REPO.to_string())
}

fn vmlinux_ref() -> String {
    std::env::var("VMLINUX_REF").unwrap_or_else(|_| DEFAULT_VMLINUX_REF.to_string())
}

fn fetch_git_repo(url: &str, git_ref: &str, local_dir: &Path) -> anyhow::Result<()> {
    let repo_dir = workdir().join(local_dir);
    if repo_dir.exists() {
        println!("Removing existsing repodir..");
        std::fs::remove_dir_all(&repo_dir)?;
    }
    if !Command::new("git")
        .current_dir(workdir())
        .arg("clone")
        .arg("--recursive")
        .arg(url)
        .arg(local_dir)
        .status()?
        .success()
    {
        bail!("Failed to clone {} repo", url);
    }
    if !Command::new("git")
        .current_dir(workdir().join(local_dir))
        .arg("checkout")
        .arg(git_ref)
        .status()?
        .success()
    {
        bail!("Failed to switch commit for {} to {}", url, git_ref);
    }

    Ok(())
}

fn fetch_and_build_bpftool() -> anyhow::Result<()> {
    fetch_git_repo(&bpftool_repo(), &bpftool_ref(), &bpftool_repodir())?;
    if !Command::new("make")
        .current_dir(workdir().join(bpftool_repodir()).join("src"))
        .status()?
        .success()
    {
        bail!("Failed to build bpftool");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=BPFTOOL_REPO");
    println!("cargo:rerun-if-env-changed=BPFTOOL_REF");
    println!("cargo:rerun-if-env-changed=VMLINUX_REPO");
    println!("cargo:rerun-if-env-changed=VMLINUX_REF");
    println!("cargo:rerun-if-changed=workspace");

    let workspace_path =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("workspace");

    fetch_and_build_bpftool()?;
    fetch_git_repo(&vmlinux_repo(), &vmlinux_ref(), &vmlinux_repodir())
        .with_context(|| anyhow!("Failed to fetch vmlinux headers"))?;
    if workspace_path.exists() {
        println!("Removing existsing workspace..");
        std::fs::remove_dir_all(&workspace_path)
            .with_context(|| anyhow!("Failed to remove existsing workspace dir"))?;
    }
    std::fs::create_dir_all(&workspace_path)
        .with_context(|| anyhow!("Failed to create workspace dir"))?;
    std::fs::create_dir_all(workspace_path.join("bin"))?;
    std::fs::create_dir_all(workspace_path.join("include"))?;
    let bpftool_repo_dir = workdir().join(bpftool_repodir());
    std::fs::copy(
        bpftool_repo_dir.join("src/bpftool"),
        workspace_path.join("bin/bpftool"),
    )
    .with_context(|| anyhow!("Failed to copy bpftool binary"))?;
    fs_extra::dir::copy(
        bpftool_repo_dir.join("src/libbpf/include/bpf"),
        workspace_path.join("include"),
        &CopyOptions::default(),
    )
    .with_context(|| anyhow!("Failed to copy libbpf headers"))?;
    fs_extra::dir::copy(
        workdir().join(vmlinux_repodir()),
        workspace_path.join("include"),
        &CopyOptions::default().copy_inside(true),
    )
    .with_context(|| anyhow!("Failed to copy vmlinux headers"))?;
    Ok(())
}
