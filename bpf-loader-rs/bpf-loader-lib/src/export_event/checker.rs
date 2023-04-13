//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{anyhow, bail, Result};
use btf::types::{Btf, BtfType};
use log::warn;

use crate::meta::{ExportedTypesStructMemberMeta, ExportedTypesStructMeta};

use super::CheckedExportedMember;
#[inline]
pub(crate) fn check_export_types_btf(
    struct_meta: &ExportedTypesStructMeta,
    btf: &Btf,
) -> Result<Vec<CheckedExportedMember>> {
    let ty = btf
        .types()
        .get(struct_meta.type_id as usize)
        .ok_or_else(|| anyhow!("type id {} is invalid", struct_meta.type_id))?;
    if let BtfType::Struct(st) = ty {
        if ty.name() != struct_meta.name {
            bail!(
                "type names don't match: `{}` from btf, but `{}` from struct_meta",
                ty.name(),
                struct_meta.name
            );
        }
        if st.members.len() != struct_meta.members.len() {
            bail!(
                "Unmatched member count: `{}` from btf, but `{}` from struct_meta",
                st.members.len(),
                struct_meta.members.len()
            );
        }
        let mut result = vec![];
        for (btf_mem, meta_mem) in st.members.iter().zip(struct_meta.members.iter()) {
            if btf_mem.name != meta_mem.name {
                continue;
            }
            let type_id = btf_mem.type_id;
            // The original C++ code is:
            // ```
            // if (BTF_INFO_KFLAG(t->info)) {
            //     bit_off = BTF_MEMBER_BIT_OFFSET(m->offset);
            //     bit_sz = BTF_MEMBER_BITFIELD_SIZE(m->offset);
            // } else {
            //     bit_off = m->offset;
            //     bit_sz = 0;
            // }
            // ```
            // But there is no need to check if `t` is a struct, since we already ensure through the previous if-let statements
            let bit_off = btf_mem.bit_offset;

            let bit_sz = btf_mem.bit_size;
            let size = btf.get_size_of(btf_mem.type_id);
            if bit_off % 8 != 0 || bit_sz % 8 != 0 {
                bail!(
                    "Bitfield is not supported. Member {}, bit_offset={}, bit_sz={}",
                    btf_mem.name,
                    bit_off,
                    bit_sz
                );
            }

            result.push(CheckedExportedMember {
                meta: meta_mem.clone(),
                type_id,
                bit_offset: bit_off,
                size: size as usize,
                bit_size: bit_sz as u32,
                output_header_offset: 0,
            });
        }
        Ok(result)
    } else {
        bail!("type id {} is not struct", struct_meta.type_id);
    }
}

pub(crate) fn check_sample_types_btf(
    btf: &Btf,
    type_id: u32,
    mut members: Option<ExportedTypesStructMeta>,
) -> Result<Vec<CheckedExportedMember>> {
    let ty = btf
        .types()
        .get(type_id as usize)
        .ok_or_else(|| anyhow!("Invalid type id: {}", type_id))?;
    if let Some(local_members) = members.as_ref() {
        if local_members.name != ty.name() {
            warn!(
                "Unmatched type name: `{}` from btf, `{}` from exported types struct meta",
                ty.name(),
                local_members.name
            );
            members.take();
        }
    }
    let mut result = vec![];
    if let BtfType::Struct(comp) = ty {
        if let Some(local_members) = members.as_ref() {
            if comp.members.len() != local_members.members.len() {
                warn!(
                    "Members count mismatched: {} from btf, {} from exported types struct meta",
                    comp.members.len(),
                    local_members.members.len()
                );
                members.take();
            }
        }
        for (i, btf_mem) in comp.members.iter().enumerate() {
            let mem_type_id = btf_mem.type_id;
            let bit_off = btf_mem.bit_offset;
            let bit_sz = btf_mem.bit_size;
            check_and_push_export_type_btf(
                btf,
                mem_type_id,
                bit_off,
                bit_sz as _,
                &mut result,
                members.as_ref().map(|v| v.members[i].clone()),
            )?;
        }
    } else {
        check_and_push_export_type_btf(btf, type_id, 0, 0, &mut result, None)?;
    }
    Ok(result)
}

fn check_and_push_export_type_btf(
    btf: &Btf,
    type_id: u32,
    bit_off: u32,
    bit_sz: u32,
    out: &mut Vec<CheckedExportedMember>,
    member_meta: Option<ExportedTypesStructMemberMeta>,
) -> Result<()> {
    let ty = btf
        .types()
        .get(type_id as usize)
        .ok_or_else(|| anyhow!("Invalid type id: {}", type_id))?;
    let size = btf.get_size_of(type_id);
    let member_meta = if let Some(meta) = member_meta {
        meta
    } else {
        ExportedTypesStructMemberMeta {
            name: ty.name().to_owned(),
            ty: ty.to_string(),
        }
    };
    out.push(CheckedExportedMember {
        meta: member_meta,
        type_id,
        bit_offset: bit_off,
        size: size as usize,
        bit_size: bit_sz,
        output_header_offset: 0,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use btf::types::BtfType;

    use crate::{btf_container::BtfContainer, meta::EunomiaObjectMeta, tests::get_assets_dir};

    use super::check_export_types_btf;

    #[test]
    fn test_check_export_types_btf_1() {
        let assets_dir = get_assets_dir();
        let btf_container = BtfContainer::new_from_binary(
            &std::fs::read(assets_dir.join("simple_prog").join("simple_prog.bpf.o")).unwrap()[..],
        )
        .unwrap();
        let eunomia_meta: EunomiaObjectMeta = serde_json::from_str(
            &std::fs::read_to_string(assets_dir.join("simple_prog").join("simple_prog.skel.json"))
                .unwrap(),
        )
        .unwrap();
        let struct_meta = &eunomia_meta.export_types[0];
        let btf = btf_container.borrow_btf();
        let checked_types = check_export_types_btf(struct_meta, btf).unwrap();
        println!("{:#?}", checked_types);

        let st = if let BtfType::Struct(st) = btf.type_by_id(2) {
            st
        } else {
            panic!("Unexpected type")
        };
        for (a, b) in checked_types.iter().zip(st.members.iter()) {
            assert_eq!(a.bit_offset, b.bit_offset);
            assert_eq!(a.bit_size, b.bit_size as u32);
            assert_eq!(a.size, btf.get_size_of(b.type_id) as usize);
            assert_eq!(a.type_id, b.type_id);
            assert_eq!(a.meta.name, b.name);
        }
    }
}
