//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::collections::HashMap;

use anyhow::anyhow;
use anyhow::{bail, Result};
use btf::types::{Btf, BtfType};
use log::info;
use serde_json::Value;

use crate::helper::btf::BtfHelper;
use crate::meta::DataSectionMeta;

fn paste_bytes(buf: &mut [u8], ty: &SectionVariableDecl, bytes: &[u8]) -> Result<()> {
    let range = buf
        .get_mut(ty.offset as usize..(ty.offset + ty.size) as usize)
        .ok_or_else(|| {
            anyhow!(
                "Invalid range in the original buffer: {}..{}",
                ty.offset,
                ty.offset + ty.size
            )
        })?;
    if bytes.len() != ty.size as usize {
        bail!("Expected a slice with length {}", ty.size);
    }
    range.copy_from_slice(bytes);
    Ok(())
}
macro_rules! decl_integer_conversions {
    ($size: expr, $num: expr, $var_name: expr, $(($bytes: expr, $out_type: ty)), *) => {
       { let vec:Vec<u8> = match $size {
            $(
                $bytes => TryInto::<$out_type>::try_into($num).map_err(|e| anyhow!("Overflow at variable {}: {}", $var_name, e))?
                .to_le_bytes().into(),
            )*
            s => anyhow::bail!("Unsupported integer bytes: {}",s)
        };
        vec}
    };
}
pub(crate) fn load_section_data(
    btf: &Btf,
    section: &DataSectionMeta,
    buffer: &mut [u8],
) -> Result<()> {
    let btf_type_map = resolve_btf_section_variable_types(section, btf)?;
    for variable in section.variables.iter() {
        let btf_type = btf_type_map
            .get(&variable.name)
            .ok_or_else(|| anyhow!("Variable named `{}` does not exist in btf", variable.name))?;
        if let Some(value) = &variable.value {
            let real_type = btf
                .types()
                .get(btf.resolve_real_type(btf_type.type_id)? as usize)
                .ok_or_else(|| anyhow!("Invalid type"))?;
            info!(
                "load runtime arg for {}: {:?}, real_type={}, btf_type={:?}",
                variable.name, value, real_type, btf_type
            );

            match (value, real_type) {
                (Value::Number(num), BtfType::Int(_)) if num.is_i64() => {
                    let num = num.as_i64().unwrap();
                    let bytes = decl_integer_conversions!(
                        btf_type.size,
                        num,
                        variable.name,
                        (1, i8),
                        (2, i16),
                        (4, i32),
                        (8, i64)
                    );
                    paste_bytes(buffer, btf_type, &bytes[..])?;
                    info!("received bytes {:?}", bytes);
                }
                (Value::Number(num), BtfType::Int(_)) if num.is_u64() => {
                    let num = num.as_u64().unwrap();
                    let bytes = decl_integer_conversions!(
                        btf_type.size,
                        num,
                        variable.name,
                        (1, u8),
                        (2, u16),
                        (4, u32),
                        (8, u64)
                    );
                    paste_bytes(buffer, btf_type, &bytes[..])?;
                }
                (Value::Number(num), BtfType::Float(btf_float)) => {
                    let f64v = num.as_f64().ok_or_else(|| {
                        anyhow!("Expect a float for variable `{}`", variable.name)
                    })?;
                    match btf_float.sz {
                        4 => paste_bytes(
                            buffer,
                            btf_type,
                            &((f64v as f32).to_be_bytes() as [u8; 4]),
                        )?,
                        8 => paste_bytes(
                            buffer,
                            btf_type,
                            #[allow(clippy::unnecessary_cast)]
                            &((f64v as f64).to_be_bytes() as [u8; 8]),
                        )?,
                        s => bail!(
                            "Unsupported float size `{}` for variable `{}`",
                            s,
                            variable.name
                        ),
                    };
                }
                (Value::Bool(json_bool), BtfType::Int(btf_int)) if btf_int.bits == 8 => {
                    paste_bytes(buffer, btf_type, &(if *json_bool { [1u8] } else { [0u8] }))?
                }
                (Value::String(s), _) if btf.is_char_array(btf_type.type_id)? => {
                    let mut bytes = s.as_bytes().to_vec();
                    // Traling zero
                    bytes.push(0);
                    if bytes.len() > btf_type.size as usize {
                        bail!("String in variable `{}` is too long. Received a string with {} bytes, but only {} bytes is allowed",variable.name,bytes.len(),btf_type.size);
                    } else {
                        // Copy at most bytes.len()
                        buffer
                            .get_mut(
                                btf_type.offset as usize
                                    ..btf_type.offset as usize
                                        + bytes.len().min(btf_type.size as usize),
                            )
                            .ok_or_else(|| anyhow!("Invalid slice"))?
                            .copy_from_slice(&bytes);
                    };
                }
                (val, btf_ty) => {
                    bail!(
                        "Unsupported (JsonValue, BtfValue) pair: {:?} {}",
                        val,
                        btf_ty
                    );
                }
            }
        }
    }
    Ok(())
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SectionVariableDecl {
    type_id: u32,
    size: u32,
    offset: u32,
}
pub(crate) fn resolve_btf_section_variable_types(
    section: &DataSectionMeta,
    btf: &Btf,
) -> Result<HashMap<String, SectionVariableDecl>> {
    let mut result = HashMap::default();
    let sec_ty = btf
        .types()
        .iter()
        .find(|ty| ty.name() == section.name)
        .ok_or_else(|| {
            anyhow!(
                "Cannot find a type named `{}` in the provided btf info",
                section.name
            )
        })?;

    if let BtfType::Datasec(data_sec) = sec_ty {
        let mut next_pos = 0;
        for (i, var) in data_sec.vars.iter().enumerate() {
            if var.offset < next_pos {
                bail!("Variable #{} (type id {}, offset {}, size {}) in section `{}` overflapped with a previous variable",i,var.type_id,var.offset,var.sz,section.name);
            }
            let ty_var = btf
                .types()
                .get(var.type_id as usize)
                .ok_or_else(|| anyhow!("Variable typeid {} is invalid", var.type_id))?;
            let ty_var = match ty_var {
                BtfType::Var(v) => v,
                _ => bail!(
                    "Variable type id {} is expected to be a BTF_KIND_VAR element",
                    var.type_id
                ),
            };

            result.insert(
                ty_var.name.into(),
                SectionVariableDecl {
                    type_id: ty_var.type_id,
                    size: var.sz,
                    offset: var.offset,
                },
            );

            next_pos = var.offset + var.sz;
        }
    } else {
        bail!("Type named `{}` is not datasec", sec_ty.name());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        meta::ComposedObject,
        skeleton::{builder::BpfSkeletonBuilder, preload::section_loader::SectionVariableDecl},
        tests::get_assets_dir,
    };

    use super::{load_section_data, resolve_btf_section_variable_types};

    #[test]
    fn test_resolve_btf_types() {
        let runqlat_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(get_assets_dir().join("runqlat.json")).unwrap(),
        )
        .unwrap();
        let skel = BpfSkeletonBuilder::from_json_package(&runqlat_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let loaded_types =
            resolve_btf_section_variable_types(&runqlat_json.meta.bpf_skel.data_sections[0], btf)
                .unwrap();
        for (k, v) in loaded_types.iter() {
            println!("{} -> {}; {:?}", k, btf.type_by_id(v.type_id), v);
        }
        assert_eq!(
            loaded_types["filter_cg"],
            SectionVariableDecl {
                offset: 0,
                size: 1,
                type_id: 606
            }
        );
        assert_eq!(
            loaded_types["targ_per_process"],
            SectionVariableDecl {
                offset: 1,
                size: 1,
                type_id: 606
            }
        );
        assert_eq!(
            loaded_types["targ_per_thread"],
            SectionVariableDecl {
                offset: 2,
                size: 1,
                type_id: 606
            }
        );
        assert_eq!(
            loaded_types["targ_per_pidns"],
            SectionVariableDecl {
                offset: 3,
                size: 1,
                type_id: 606
            }
        );
        assert_eq!(
            loaded_types["targ_ms"],
            SectionVariableDecl {
                offset: 4,
                size: 1,
                type_id: 606
            }
        );
        assert_eq!(
            loaded_types["targ_tgid"],
            SectionVariableDecl {
                offset: 8,
                size: 4,
                type_id: 613
            }
        );
    }
    #[test]
    // Test loading integers and bools
    fn test_load_section_1() {
        let mut runqlat_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(get_assets_dir().join("runqlat.json")).unwrap(),
        )
        .unwrap();
        runqlat_json.meta.bpf_skel.data_sections[0]
            .variables
            .iter_mut()
            .for_each(|s| {
                if s.ty == "bool" {
                    s.value = Some(json!(true));
                } else if s.ty == "pid_t" {
                    s.value = Some(json!(0x12345678));
                }
            });
        let skel = BpfSkeletonBuilder::from_json_package(&runqlat_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let mut buf = vec![0u8; skel.map_value_sizes["runqlat_.rodata"] as usize];
        load_section_data(btf, &runqlat_json.meta.bpf_skel.data_sections[0], &mut buf).unwrap();
        println!("{:?}", buf);
        assert_eq!(buf, &[1, 1, 1, 1, 1, 0, 0, 0, 120, 86, 52, 18]);
    }
    #[test]
    #[should_panic = "pair: Number(1.2345) <INT> '_Bool' bits:8 off:0 enc:bool"]
    // Test loading illegal values - floats on integer fields
    fn test_load_section_2() {
        let mut runqlat_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(get_assets_dir().join("runqlat.json")).unwrap(),
        )
        .unwrap();
        runqlat_json.meta.bpf_skel.data_sections[0]
            .variables
            .iter_mut()
            .for_each(|s| {
                if s.name == "filter_cg" {
                    s.value = Some(json!(1.2345));
                }
            });
        let skel = BpfSkeletonBuilder::from_json_package(&runqlat_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let mut buf = vec![0u8; skel.map_value_sizes["runqlat_.rodata"] as usize];
        load_section_data(btf, &runqlat_json.meta.bpf_skel.data_sections[0], &mut buf).unwrap();
    }
    #[test]
    #[should_panic = "Overflow at variable targ_tgid: out of range integral type conversion attempted"]
    // Test loading illegal values - overflowed integers
    fn test_load_section_3() {
        let mut runqlat_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(get_assets_dir().join("runqlat.json")).unwrap(),
        )
        .unwrap();
        runqlat_json.meta.bpf_skel.data_sections[0]
            .variables
            .iter_mut()
            .for_each(|s| {
                if s.name == "targ_tgid" {
                    s.value = Some(json!(0x1234567890abcdefi64));
                }
            });
        let skel = BpfSkeletonBuilder::from_json_package(&runqlat_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let mut buf = vec![0u8; skel.map_value_sizes["runqlat_.rodata"] as usize];
        load_section_data(btf, &runqlat_json.meta.bpf_skel.data_sections[0], &mut buf).unwrap();
    }
    #[test]
    // Test load strings
    fn test_load_section_4() {
        let mut sp2_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(
                get_assets_dir()
                    .join("simple_prog_2")
                    .join("simple_prog_2.package.json"),
            )
            .unwrap(),
        )
        .unwrap();
        sp2_json.meta.bpf_skel.data_sections[0]
            .variables
            .iter_mut()
            .for_each(|s| {
                if s.name == "const_buf" {
                    s.value = Some(json!("123567"));
                }
            });
        let skel = BpfSkeletonBuilder::from_json_package(&sp2_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let mut buf = vec![0u8; skel.map_value_sizes["simple_p.rodata"] as usize];
        load_section_data(btf, &sp2_json.meta.bpf_skel.data_sections[0], &mut buf).unwrap();
        assert_eq!(&buf[..6], &[49, 50, 51, 53, 54, 55]);
    }
    #[test]
    #[should_panic = "String in variable `const_buf` is too long. Received a string with 201 bytes, but only 100 bytes is allowed"]
    // Test load too long strings
    fn test_load_section_5() {
        let mut sp2_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(
                get_assets_dir()
                    .join("simple_prog_2")
                    .join("simple_prog_2.package.json"),
            )
            .unwrap(),
        )
        .unwrap();
        sp2_json.meta.bpf_skel.data_sections[0]
            .variables
            .iter_mut()
            .for_each(|s| {
                if s.name == "const_buf" {
                    s.value = Some(json!("aa".repeat(100)));
                }
            });
        let skel = BpfSkeletonBuilder::from_json_package(&sp2_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let mut buf = vec![0u8; skel.map_value_sizes["simple_p.rodata"] as usize];
        load_section_data(btf, &sp2_json.meta.bpf_skel.data_sections[0], &mut buf).unwrap();
    }
    #[test]
    // Test load floats
    fn test_load_section_6() {
        let mut sp2_json: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(
                get_assets_dir()
                    .join("simple_prog_2")
                    .join("simple_prog_2.package.json"),
            )
            .unwrap(),
        )
        .unwrap();
        sp2_json.meta.bpf_skel.data_sections[0]
            .variables
            .iter_mut()
            .for_each(|s| {
                if s.name == "const_f1" {
                    s.value = Some(json!(1.2345));
                }
            });
        let skel = BpfSkeletonBuilder::from_json_package(&sp2_json, None)
            .build()
            .unwrap();
        let btf = skel.btf.borrow_btf();
        let mut buf = vec![0u8; skel.map_value_sizes["simple_p.rodata"] as usize];
        load_section_data(btf, &sp2_json.meta.bpf_skel.data_sections[0], &mut buf).unwrap();
        println!("{:?}", buf);
        assert_eq!(&buf[buf.len() - 4..], &[63, 158, 4, 25]);
    }
}
