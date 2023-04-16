//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{
    collections::HashMap,
    ffi::{c_void, CStr},
    os::{
        raw::c_char,
        unix::prelude::{OsStrExt, PermissionsExt},
    },
    path::PathBuf,
    ptr::NonNull,
};

use crate::{
    btf_container::BtfContainer,
    helper::btf::{create_elf_with_btf_section, get_current_system_btf_file},
    meta::{ComposedObject, EunomiaObjectMeta, RunnerConfig},
    skeleton::{BTF_PATH_ENV_NAME, VMLINUX_BTF_PATH},
};
use anyhow::{anyhow, bail, Result};
use libbpf_rs::{
    libbpf_sys::{
        self, bpf_map__name, bpf_map__value_size, bpf_object__btf, bpf_object__next_map,
        btf__get_raw_data,
    },
    ObjectBuilder, OpenObject,
};

use super::preload::PreLoadBpfSkeleton;

/// Builder of BpfSkeleton
pub struct BpfSkeletonBuilder<'a> {
    btf_archive_path: Option<&'a str>,
    object_meta: &'a EunomiaObjectMeta,
    bpf_object: &'a [u8],
    runner_config: Option<RunnerConfig>,
}

impl<'a> BpfSkeletonBuilder<'a> {
    /// Create a builder using provided meta and bpj_object
    /// btf_archive_path - Path to the root of kernel btf archives, if not provided, will try to use env var `BTF_FILEP_PATH` and /sys/kernel/btf/vmlinux
    pub fn from_object_meta_and_object_buffer(
        meta: &'a EunomiaObjectMeta,
        bpf_object: &'a [u8],
        btf_archive_path: Option<&'a str>,
    ) -> Self {
        Self {
            btf_archive_path,
            object_meta: meta,
            bpf_object,
            runner_config: None,
        }
    }
    /// Create a builder from the json package
    /// btf_archive_path - Path to the root of kernel btf archives, if not provided, will try to use env var `BTF_FILEP_PATH` and /sys/kernel/btf/vmlinux
    pub fn from_json_package(
        package: &'a ComposedObject,
        btf_archive_path: Option<&'a str>,
    ) -> Self {
        Self::from_object_meta_and_object_buffer(
            &package.meta,
            &package.bpf_object,
            btf_archive_path,
        )
    }
    /// Set the runner_config of this bpf program
    pub fn set_runner_config(self, cfg: RunnerConfig) -> Self {
        Self {
            runner_config: Some(cfg),
            ..self
        }
    }
    /// Build (open) the skeleton
    pub fn build(self) -> Result<PreLoadBpfSkeleton> {
        let mut open_bpts = ObjectBuilder::default()
            .opts(self.object_meta.bpf_skel.obj_name.as_bytes().as_ptr() as *const c_char);
        // Why we put path_holder here? to keep its iveness until this function returns, so that we can safely use the pointers to the underlying data in bpf_object_openopts
        let path_holder = if let Some(base_path) = self.btf_archive_path.as_ref() {
            let path = get_current_system_btf_file(PathBuf::from(base_path).as_path())?;
            if !path.exists() {
                bail!("BTF file not found for current system: {}", path.display());
            }
            Some(path)
        } else {
            None
        };
        // Ditto
        let env_btf_file_path = std::env::var_os(BTF_PATH_ENV_NAME);

        let vmlinux_btf_exists = if PathBuf::from(VMLINUX_BTF_PATH).exists() {
            match std::fs::metadata(VMLINUX_BTF_PATH) {
                Ok(meta) => {
                    // Tests if we have S_IRUSR permission
                    meta.permissions().mode() & 0o0400 != 0
                }
                Err(e) => {
                    log::info!("Failed to get metadata of {}: {}", VMLINUX_BTF_PATH, e);
                    false
                }
            }
        } else {
            false
        };
        if path_holder.is_some() && !vmlinux_btf_exists {
            // We have to manually modify open_opts and open bpf_object, because libbpf-rs currently doesn't support customizing this..

            // SAFETY: path_holder will lives until this function returns
            open_bpts.btf_custom_path = path_holder
                .as_ref()
                .unwrap()
                .as_os_str()
                .as_bytes()
                .as_ptr() as *const i8;
        } else if let Some(env_btf) = env_btf_file_path.as_ref() {
            // SAFETY: env_btf_file_path will live until this function returns
            open_bpts.btf_custom_path = env_btf.as_bytes().as_ptr() as *const i8;
        } else if !vmlinux_btf_exists {
            bail!("All ways tried to find vmlinux BTF, but not found. Please provide the vmlinux btf using env `BTF_FILE_PATH`. (Tried parameter `btf_archive_path`, {}, and {})",BTF_PATH_ENV_NAME,VMLINUX_BTF_PATH);
        };
        // SAFETY: FFI call. Pointers passed in will live during the call
        let open_result = unsafe {
            libbpf_sys::bpf_object__open_mem(
                self.bpf_object.as_ptr() as *const c_void,
                self.bpf_object.len() as libbpf_sys::size_t,
                &open_bpts,
            )
        };
        if open_result.is_null() {
            bail!(
                "Failed to open bpf object: bpf_object__open_mem returned NULL with errno={}",
                errno::errno()
            );
        }

        // Retrive the btf archive from the loaded bpf_object
        let btf = {
            // SAFETY: This function will always succeed
            let btf = unsafe { bpf_object__btf(open_result) };
            if btf.is_null() {
                bail!("Failed to get btf* from the bpf_object: {}", errno::errno());
            }
            // Dump the original data
            let mut dumped_size: u32 = 0;
            // SAFETY: It will never fault, since btf is valid
            let raw_data = unsafe { btf__get_raw_data(btf, &mut dumped_size as *mut u32) };
            if raw_data.is_null() {
                bail!(
                    "Failed to get the raw btf data from btf *: {}",
                    errno::errno()
                );
            }
            // SAFETY: btf__get_raw_data ensured that only dumped_size bytes can be used
            // The slice will never be used once this block exits, it will be cloned in BtfContainer
            let data =
                unsafe { std::slice::from_raw_parts(raw_data as *const u8, dumped_size as usize) };
            BtfContainer::new_from_binary(&create_elf_with_btf_section(data, true)?)?
        };

        let map_value_sizes = {
            let mut sizes = HashMap::default();
            let mut curr_map = std::ptr::null();
            loop {
                // SAFETY: it's always to call this, since open_result and curr_map are all valid
                curr_map = unsafe { bpf_object__next_map(open_result, curr_map) };
                if curr_map.is_null() {
                    break;
                }
                // SAFETY: libbpf ensures that the map name is valid
                let map_name = unsafe { CStr::from_ptr(bpf_map__name(curr_map)) }
                    .to_str()
                    .map_err(|e| anyhow!("Map name contains invalid character: {}", e))?;
                // SAFETY: curr_map is valid
                let value_size = unsafe { bpf_map__value_size(curr_map) };
                sizes.insert(map_name.into(), value_size);
            }
            sizes
        };
        // SAFETY: The pointer won't be used by us anymore, and we also checked if it's null
        let open_object = unsafe { OpenObject::from_ptr(NonNull::new_unchecked(open_result)) }?;

        Ok(PreLoadBpfSkeleton {
            bpf_object: open_object,
            config_data: self.runner_config.unwrap_or_default(),
            btf,
            meta: self.object_meta.clone(),
            map_value_sizes,
        })
    }
}

#[cfg(test)]
#[cfg(not(feature = "no-load-bpf-tests"))]
mod tests {
    use libbpf_rs::libbpf_sys::{bpf_map__fd, bpf_map__initial_value, size_t};

    use crate::{
        meta::ComposedObject, skeleton::builder::BpfSkeletonBuilder, tests::get_assets_dir,
    };

    #[test]
    fn test_bpf_skeleton_builder_1() {
        let package = serde_json::from_str::<ComposedObject>(
            &std::fs::read_to_string(get_assets_dir().join("runqlat.json")).unwrap(),
        )
        .unwrap();
        let preload = BpfSkeletonBuilder::from_json_package(&package, None)
            .build()
            .unwrap();
        // Check the maps
        let bpf_object = preload.bpf_object;
        for map in package.meta.bpf_skel.maps.iter() {
            let map_from_bpf = bpf_object.map(map.name.as_str()).unwrap();
            println!("{:?}", map_from_bpf);
        }
        // Check the progs
        for prog in package.meta.bpf_skel.progs.iter() {
            let prog_from_bpf = bpf_object.prog(prog.name.as_str()).unwrap();
            println!("{:?}", prog_from_bpf);
        }
        {
            let s = bpf_object.load().unwrap();
            for map in s.maps_iter() {
                let mptr = map.as_libbpf_bpf_map_ptr().unwrap();
                let mut s: size_t = 0;
                let ptr = unsafe { bpf_map__initial_value(mptr.as_ptr(), &mut s as *mut _) };
                println!(
                    "{} key size {} value size {} max ent {} mmapedptr {:?} mmaped size {} fd {}",
                    map.name(),
                    map.key_size(),
                    map.value_size(),
                    map.info().unwrap().info.max_entries,
                    ptr,
                    s,
                    unsafe { bpf_map__fd(mptr.as_ptr()) }
                );
            }
        }
    }
}
