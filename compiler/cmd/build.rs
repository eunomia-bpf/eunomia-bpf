//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context};
use dircpy::copy_dir;
use dircpy::CopyBuilder;

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
    println!("cargo:rerun-if-env-changed=ECC_CUSTOM_WORKSPACE_ROOT");

    let workspace_path = workdir().join("workspace");

    if workspace_path.exists() {
        println!("Removing existsing workspace..");
        std::fs::remove_dir_all(&workspace_path)
            .with_context(|| anyhow!("Failed to remove existsing workspace dir"))?;
    }
    std::fs::create_dir_all(&workspace_path)
        .with_context(|| anyhow!("Failed to create workspace dir"))?;

    if let Ok(v) = std::env::var("ECC_CUSTOM_WORKSPACE_ROOT") {
        println!("Copying custom workspace from {}", v);
        copy_dir(v, workspace_path).with_context(|| anyhow!("Failed to copy custom workspace"))?;
        return Ok(());
    }
    fetch_and_build_bpftool()
        .with_context(|| anyhow!("Failed to fetch or build the repo of bpftool"))?;
    fetch_git_repo(&vmlinux_repo(), &vmlinux_ref(), &vmlinux_repodir())
        .with_context(|| anyhow!("Failed to fetch vmlinux headers"))?;

    std::fs::create_dir_all(workspace_path.join("bin"))
        .with_context(|| anyhow!("Failed to create `bin` directory of workspace"))?;
    std::fs::create_dir_all(workspace_path.join("include"))
        .with_context(|| anyhow!("Failed to create `include` directory of workspace"))?;
    let bpftool_repo_dir = workdir().join(bpftool_repodir());
    std::fs::copy(
        bpftool_repo_dir.join("src/bpftool"),
        workspace_path.join("bin/bpftool"),
    )
    .with_context(|| anyhow!("Failed to copy bpftool binary"))?;
    copy_dir(
        bpftool_repo_dir.join("src/libbpf/include/bpf"),
        workspace_path.join("include/bpf"),
    )
    .with_context(|| anyhow!("Failed to copy libbpf headers"))?;
    // Avoid copying the .git folder
    std::fs::remove_dir_all(workdir().join(vmlinux_repodir()).join(".git"))
        .with_context(|| anyhow!("Failed to remove .git directory "))?;
    CopyBuilder::new(
        workdir().join(vmlinux_repodir()),
        workspace_path.join("include/vmlinux"),
    )
    .run()
    .with_context(|| anyhow!("Failed to copy vmlinux headers"))?;
    Ok(())
}
