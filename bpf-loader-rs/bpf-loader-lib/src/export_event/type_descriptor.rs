//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use anyhow::{anyhow, bail, Result};
use btf::types::{Btf, BtfType};

use crate::{helper::btf::BtfHelper, meta::OverridedStructMember};

/// Indicates a checked (able to directly used) struct member of a map's export type
#[derive(Debug, Clone)]
pub struct CheckedExportedMember {
    pub(crate) field_name: String,
    pub(crate) type_id: u32,
    pub(crate) bit_offset: u32,
    pub(crate) size: usize,
    pub(crate) output_header_offset: usize,
}
/// Describe the source to obtain `Vec<CheckedExportedStructMember>` of a certain map
pub enum TypeDescriptor {
    /// Use user overrided members
    ManuallyOverride(Vec<OverridedStructMember>),
    /// Use a struct described in the BTF
    BtfType { type_id: u32 },
    /// Directly use there checked members. Keep compatibilities to the old version
    CheckedMembers(Vec<CheckedExportedMember>),
}

impl TypeDescriptor {
    pub(crate) fn build_checked_exported_members(
        self,
        btf: &Btf,
    ) -> Result<Vec<CheckedExportedMember>> {
        let ret = match self {
            Self::ManuallyOverride(mut override_mems) => {
                let mut result = vec![];
                let mut last_pos = 0usize;
                override_mems.sort_by_key(|v| v.offset);
                for mem in override_mems.into_iter() {
                    if btf.types().get(mem.btf_type_id as usize).is_none() {
                        bail!(
                            "Invalid type id {} for overridden member {}",
                            mem.btf_type_id,
                            mem.name
                        );
                    }
                    if mem.offset < last_pos {
                        bail!("Field `{}` overflapped with other fields", mem.name);
                    }
                    last_pos = mem.offset + btf.get_size_of(mem.btf_type_id) as usize;
                    result.push(CheckedExportedMember {
                        field_name: mem.name,
                        type_id: mem.btf_type_id,
                        bit_offset: (mem.offset * 8) as u32,
                        size: btf.get_size_of(mem.btf_type_id) as usize,
                        output_header_offset: 0,
                    });
                }
                result
            }
            Self::BtfType { type_id } => {
                let ty = btf
                    .types()
                    .get(type_id as usize)
                    .ok_or_else(|| anyhow!("Invalid btf type id: {}", type_id))?;
                if let BtfType::Struct(st) = ty {
                    let mut result = vec![];
                    for member in st.members.iter() {
                        if member.bit_offset % 8 != 0 {
                            bail!("Bit offset of member {} is not divisible by 8", member.name);
                        }
                        result.push(CheckedExportedMember {
                            bit_offset: member.bit_offset,
                            field_name: member.name.to_string(),
                            output_header_offset: 0,
                            size: btf.get_size_of(member.type_id) as usize,
                            type_id: member.type_id,
                        });
                    }
                    result
                } else if matches!(
                    btf.type_by_id(btf.resolve_real_type(type_id)?),
                    BtfType::Array(_) | BtfType::Int(_) | BtfType::Float(_) | BtfType::Ptr(_)
                ) {
                    vec![CheckedExportedMember {
                        bit_offset: 0,
                        type_id,
                        field_name: "".to_string(),
                        output_header_offset: 0,
                        size: btf.get_size_of(type_id) as usize,
                    }]
                } else {
                    bail!("Unsupported type when building exporter: {}", type_id)
                }
            }
            Self::CheckedMembers(v) => v,
        };
        Ok(ret)
    }
}
