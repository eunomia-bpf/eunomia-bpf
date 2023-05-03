//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, Result};
use btf::types::Btf;
use ouroboros::self_referencing;

use crate::elf_container::ElfContainer;
/// A helper struct to solve the reference problem of btf::types::Btf
/// This struct contains the binary of the original elf file, the ElfFile struct and Btf struct.
/// With this we don't need to take care of the reference problem anymore
#[self_referencing]
pub struct BtfContainer {
    pub(crate) elf_container: ElfContainer,
    #[borrows(elf_container)]
    #[covariant]
    pub(crate) btf: Btf<'this>,
}

impl BtfContainer {
    /// Create a btf container from a ELF binary
    pub fn new_from_binary(bin: &[u8]) -> Result<Self> {
        let elf = ElfContainer::new_from_binary(bin)?;
        let val = BtfContainerTryBuilder {
            elf_container: elf,
            btf_builder: |elf: &ElfContainer| {
                Btf::load(elf.borrow_elf()).map_err(|e| anyhow!("Failed to build btf: {}", e))
            },
        }
        .try_build()?;
        Ok(val)
    }
}
