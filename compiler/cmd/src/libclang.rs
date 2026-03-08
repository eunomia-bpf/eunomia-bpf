//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{anyhow, Result};
use clang::Clang;
use log::warn;
use walkdir::WalkDir;

static LIBCLANG_LIBRARY: OnceLock<Arc<clang_sys::SharedLibrary>> = OnceLock::new();
static LIBCLANG_SESSION_LOCK: Mutex<()> = Mutex::new(());

fn configure_appimage_libclang_path() -> Result<()> {
    let Ok(search_paths) = std::env::var("EUNOMIA_APPIMAGE_DEFINED_LD_LIBRARY_PATH") else {
        return Ok(());
    };

    let mut libclang_path = None;
    for dir in search_paths.split(':') {
        let dir = PathBuf::from_str(dir)?;
        if !dir.exists() {
            continue;
        }
        for entry in WalkDir::new(dir) {
            let entry = entry?;
            if entry.file_type().is_file()
                && entry.file_name().to_string_lossy().starts_with("libclang")
            {
                libclang_path = entry.path().parent().map(|path| path.to_path_buf());
            }
        }
    }

    if let Some(path) = libclang_path {
        std::env::set_var("LIBCLANG_PATH", path);
    } else {
        warn!("libclang not found in EUNOMIA_APPIMAGE_DEFINED_LD_LIBRARY_PATH. Caution for library version issues.");
    }

    Ok(())
}

fn shared_library() -> Result<Arc<clang_sys::SharedLibrary>> {
    if let Some(library) = LIBCLANG_LIBRARY.get() {
        return Ok(Arc::clone(library));
    }

    let library = Arc::new(
        clang_sys::load_manually()
            .map_err(|e| anyhow!("Failed to load libclang dynamically at runtime: {}", e))?,
    );
    let _ = LIBCLANG_LIBRARY.set(Arc::clone(&library));
    Ok(library)
}

struct ThreadLibraryGuard {
    previous_library: Option<Arc<clang_sys::SharedLibrary>>,
}

impl ThreadLibraryGuard {
    fn enter() -> Result<Self> {
        configure_appimage_libclang_path()?;
        let library = shared_library()?;
        let previous_library = clang_sys::set_library(Some(library));
        Ok(Self { previous_library })
    }
}

impl Drop for ThreadLibraryGuard {
    fn drop(&mut self) {
        clang_sys::set_library(self.previous_library.take());
    }
}

pub(crate) fn with_clang<T>(f: impl FnOnce(&Clang) -> Result<T>) -> Result<T> {
    let _session_lock = LIBCLANG_SESSION_LOCK
        .lock()
        .map_err(|_| anyhow!("libclang session lock poisoned"))?;
    let _library_guard = ThreadLibraryGuard::enter()?;
    let clang = Clang::new().map_err(|e| anyhow!("Failed to create Clang instance: {}", e))?;
    f(&clang)
}
