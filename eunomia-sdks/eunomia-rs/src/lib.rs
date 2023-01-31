//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::path;

use anyhow::Result;
use std::ffi::OsString;
use std::fs::create_dir_all;
use std::iter::repeat_with;
use std::path::{Path, PathBuf};
use std::{env, fs, io, mem};

static EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";

/// Get eunomia home directory
pub fn get_eunomia_home() -> Result<String> {
    let eunomia_home = std::env::var(EUNOMIA_HOME_ENV);
    match eunomia_home {
        Ok(home) => Ok(home),
        Err(_) => match home::home_dir() {
            Some(home) => {
                let home = home.join(".eunomia");
                if !home.exists() {
                    create_dir_all(&home).unwrap()
                }
                Ok(home.to_str().unwrap().to_string())
            }
            None => Err(anyhow::anyhow!(
                "home dir not found. Please set EUNOMIA_HOME env."
            )),
        },
    }
}

pub struct TempDir {
    path: Box<Path>,
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn create_tmp_dir(path: PathBuf) -> io::Result<TempDir> {
    match fs::create_dir_all(&path) {
        // tmp workspace exist, return as well
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(TempDir {
            path: path.into_boxed_path(),
        }),
        Ok(_) => Ok(TempDir {
            path: path.into_boxed_path(),
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Cannot create temporary workspace",
        )),
    }
}

impl TempDir {
    /// Create a temporary directory with random suffix
    pub fn new() -> io::Result<TempDir> {
        let tmp_dir_from_env = &env::temp_dir();

        let mut buf = OsString::with_capacity(8 + 6);
        let mut char_buf = [0u8; 4];
        buf.push("eunomia.");

        for c in repeat_with(fastrand::alphanumeric).take(6) {
            buf.push(c.encode_utf8(&mut char_buf));
        }

        let path = tmp_dir_from_env.join(buf);

        create_tmp_dir(path)
    }

    /// Return path of temporary directory
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub fn close(mut self) -> io::Result<()> {
        let result = fs::remove_dir_all(self.path());

        self.path = PathBuf::default().into_boxed_path();

        mem::forget(self);

        result
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.path());
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{get_eunomia_home, EUNOMIA_HOME_ENV, FHS_EUNOMIA_HOME_ENTRY};

    #[test]
    fn test_get_eunomia_home() {
        let eunomia_home_from_env = std::env::var(EUNOMIA_HOME_ENV);
        let eunomia_home_from_home = home::home_dir().unwrap();

        match eunomia_home_from_env {
            Ok(path) => assert_eq!(get_eunomia_home().unwrap(), path),
            Err(_) => {
                if get_eunomia_home().is_err() {
                    assert!(true)
                }

                if eunomia_home_from_home.exists() {
                    assert_eq!(
                        get_eunomia_home().unwrap(),
                        eunomia_home_from_home
                            .join(".eunomia")
                            .into_os_string()
                            .into_string()
                            .unwrap()
                    );
                } else {
                    assert_eq!(
                        get_eunomia_home().unwrap(),
                        FHS_EUNOMIA_HOME_ENTRY.to_string()
                    )
                }
            }
        }
    }
}
