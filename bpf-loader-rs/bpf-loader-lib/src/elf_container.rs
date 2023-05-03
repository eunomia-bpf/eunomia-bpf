//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, Result};
use object::ElfFile;
use ouroboros::self_referencing;
/// A helper struct to solve the reference problem of ElfFile
/// This struct contains the binary of the original elf file and the ElfFile struct
/// With this we don't need to take care of the reference problem anymore
#[self_referencing]
pub struct ElfContainer {
    bin: Vec<u8>,
    #[borrows(bin)]
    #[covariant]
    pub(crate) elf: ElfFile<'this>,
}

impl ElfContainer {
    /// Create a container from a ELF binary
    pub fn new_from_binary(bin: &[u8]) -> Result<Self> {
        let bin = bin.to_vec();
        let val = ElfContainerTryBuilder {
            bin,
            elf_builder: |vec: &Vec<u8>| {
                ElfFile::parse(&vec[..]).map_err(|e| anyhow!("Failed to parse elf: {}", e))
            },
        }
        .try_build()?;
        Ok(val)
    }
}
