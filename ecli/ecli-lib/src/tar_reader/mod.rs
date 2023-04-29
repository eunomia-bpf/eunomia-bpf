//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::{
    error::{Error, Result},
    runner::task_manager::BtfArchivePath,
};
use log::debug;
use std::fs;
use tar::Archive;
use tempdir::TempDir;

/// Unpack a tar archive, returning the contents of `package.json`;
///
/// It will also try get the btfhub-archive path in the unpacked directory.
///
/// It will return the btf archive path and the temporary path to hold it
///
/// Note: once the tempdir was destructed, the btf archive will be deleted
pub(crate) fn unpack_tar(tar_data: &[u8]) -> Result<(Vec<u8>, BtfArchivePath)> {
    let mut archive = Archive::new(tar_data);
    let tmpdir = TempDir::new("eunomia").map_err(|e| {
        Error::Tar(format!(
            "Failed to create a temporary directory for tar contents: {}",
            e
        ))
    })?;
    let tmpdir_path = tmpdir.path();

    archive
        .unpack(tmpdir_path)
        .map_err(|e| Error::Tar(format!("Failed to unpack tar archive: {}", e)))?;

    let json_object_buffer = fs::read(tmpdir_path.join("package.json"))
        .map_err(|e| Error::IORead(format!("Cannot read packaje.json: {}", e)))?;
    let btf_archive_path = tmpdir_path.join("btfhub-archive");
    debug!("{:?}", btf_archive_path);
    let btf_archive_path = if btf_archive_path.exists() && btf_archive_path.is_dir() {
        BtfArchivePath::WithTempdir(btf_archive_path.to_string_lossy().to_string(), tmpdir)
    } else {
        BtfArchivePath::None
    };
    Ok((json_object_buffer, btf_archive_path))
}
