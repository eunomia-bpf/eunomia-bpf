//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, Result};
use btf::types::Btf;
use object::ElfFile;
use ouroboros::self_referencing;
/// A helper struct to solve the reference problem of btf::types::Btf
/// This struct contains the binary of the original elf file, the ElfFile struct and Btf struct.
/// With this we don't need to take care of the reference problem anymore
#[self_referencing]
pub struct BtfContainer {
    bin: Vec<u8>,
    #[borrows(bin)]
    #[covariant]
    pub(crate) elf: ElfFile<'this>,
    #[borrows(elf)]
    #[covariant]
    pub(crate) btf: Btf<'this>,
}

impl BtfContainer {
    /// Create a btf container from a ELF binary
    pub fn new_from_binary(bin: &[u8]) -> Result<Self> {
        let bin = bin.to_vec();
        let val = BtfContainerTryBuilder {
            bin,
            elf_builder: |vec: &Vec<u8>| {
                ElfFile::parse(&vec[..]).map_err(|e| anyhow!("Failed to parse elf: {}", e))
            },
            btf_builder: |elf: &ElfFile| {
                Btf::load(elf).map_err(|e| anyhow!("Failed to build btf: {}", e))
            },
        }
        .try_build()?;
        Ok(val)
    }
}
