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
use crate::meta::{DataSectionMeta, DataSectionVariableMeta};

fn paste_bytes(buf: &mut [u8], offset: u32, size: u32, bytes: &[u8]) -> Result<()> {
    let range = buf
        .get_mut(offset as usize..(offset + size) as usize)
        .ok_or_else(|| {
            anyhow!(
                "Invalid range in the original buffer: {}..{}",
                offset,
                offset + size
            )
        })?;
    if bytes.len() != size as usize {
        bail!("Expected a slice with length {}", size);
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
pub(crate) fn load_section_data_with_skel_value(
    btf: &Btf,
    section: &DataSectionMeta,
    buffer: &mut [u8],
) -> Result<()> {
    // let btf_type_map = resolve_btf_section_variable_types(section, btf)?;
    let var_name_lookup: HashMap<std::string::String, &DataSectionVariableMeta> =
        HashMap::from_iter(section.variables.iter().map(|v| (v.name.clone(), v)));
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
    let sec_ty = match sec_ty {
        BtfType::Datasec(sec) => sec,
        _ => bail!("Type named `{}` is not datasec", sec_ty.name()),
    };
    for var in sec_ty.vars.iter() {
        // Decl in BTF has things like DATASEC -> VAR -> concrete type
        let var_type_decl = match btf.types().get(var.type_id as usize).ok_or_else(|| {
            anyhow!(
                "Expect type {} of datasec {} exists",
                var.type_id,
                sec_ty.name
            )
        })? {
            BtfType::Var(v) => v,
            _ => bail!("Expect type {} to be BTF_KIND_VAR", var.type_id),
        };
        let user_input_value = var_name_lookup
            .get(var_type_decl.name)
            .and_then(|v| v.value.as_ref());
        if let Some(value) = &user_input_value {
            // Here the user specified the custom value, so it should be used to override the one in the ELF
            let real_type = btf
                .types()
                .get(btf.resolve_real_type(var_type_decl.type_id)? as usize)
                .ok_or_else(|| anyhow!("Invalid type"))?;
            info!(
                "load runtime arg (user specified the value through cli, or predefined in the skeleton) for {}: {:?}, real_type={}, btf_type={:?}",
                var_type_decl.name, value, real_type, var_type_decl
            );

            match (value, real_type) {
                (Value::Number(num), BtfType::Int(_)) if num.is_i64() => {
                    let num = num.as_i64().unwrap();
                    let bytes = decl_integer_conversions!(
                        var.sz,
                        num,
                        var_type_decl.name,
                        (1, i8),
                        (2, i16),
                        (4, i32),
                        (8, i64)
                    );
                    paste_bytes(buffer, var.offset, var.sz, &bytes[..])?;
                    info!("received bytes {:?}", bytes);
                }
                (Value::Number(num), BtfType::Int(_)) if num.is_u64() => {
                    let num = num.as_u64().unwrap();
                    let bytes = decl_integer_conversions!(
                        var.sz,
                        num,
                        var_type_decl.name,
                        (1, u8),
                        (2, u16),
                        (4, u32),
                        (8, u64)
                    );
                    paste_bytes(buffer, var.offset, var.sz, &bytes[..])?;
                }
                (Value::Number(num), BtfType::Float(btf_float)) => {
                    let f64v = num.as_f64().ok_or_else(|| {
                        anyhow!("Expect a float for variable `{}`", var_type_decl.name)
                    })?;
                    match btf_float.sz {
                        4 => paste_bytes(
                            buffer,
                            var.offset,
                            var.sz,
                            &((f64v as f32).to_be_bytes() as [u8; 4]),
                        )?,
                        8 => paste_bytes(
                            buffer,
                            var.offset,
                            var.sz,
                            #[allow(clippy::unnecessary_cast)]
                            &((f64v as f64).to_be_bytes() as [u8; 8]),
                        )?,
                        s => bail!(
                            "Unsupported float size `{}` for variable `{}`",
                            s,
                            var_type_decl.name
                        ),
                    };
                }
                (Value::Bool(json_bool), BtfType::Int(btf_int)) if btf_int.bits == 8 => {
                    paste_bytes(
                        buffer,
                        var.offset,
                        var.sz,
                        &(if *json_bool { [1u8] } else { [0u8] }),
                    )?
                }
                (Value::String(s), _) if btf.is_char_array(var_type_decl.type_id)? => {
                    let mut bytes = s.as_bytes().to_vec();
                    // Traling zero
                    bytes.push(0);
                    if bytes.len() > var.sz as usize {
                        bail!(
                            "String in variable `{}` is too long. \
                        Received a string with {} bytes, but only {} bytes is allowed",
                            var_type_decl.name,
                            bytes.len(),
                            var.sz
                        );
                    } else {
                        // Copy at most bytes.len()
                        buffer
                            .get_mut(
                                var.offset as usize
                                    ..var.offset as usize + bytes.len().min(var.sz as usize),
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
        } else {
            info!(
                "User didn't specify custom value for variable {}, use the default one in ELF",
                var_type_decl.name
            );
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use btf::types::BtfType;
    use object::Object;
    use serde_json::json;

    use crate::{
        btf_container::BtfContainer, meta::ComposedObject, skeleton::builder::BpfSkeletonBuilder,
        tests::get_assets_dir,
    };

    use super::load_section_data_with_skel_value;

    #[test]
    fn test_load_static_const_variables() {
        let skel: ComposedObject = serde_json::from_str(
            &std::fs::read_to_string(get_assets_dir().join("simple_prog_4").join("package.json"))
                .unwrap(),
        )
        .unwrap();
        let btf = BtfContainer::new_from_binary(&skel.bpf_object).unwrap();
        let mut rodata_bin = btf
            .borrow_elf_container()
            .borrow_elf()
            .section_data_by_name(".rodata")
            .unwrap()
            .to_vec();
        load_section_data_with_skel_value(
            &btf.borrow_btf(),
            &skel.meta.bpf_skel.data_sections[0],
            &mut rodata_bin,
        )
        .unwrap();
        // Check the variables
        let rodata_sec = btf
            .borrow_btf()
            .types()
            .iter()
            .find_map(|v| match v {
                BtfType::Datasec(d) if d.name == ".rodata" => Some(d),
                _ => None,
            })
            .unwrap();
        for var in rodata_sec.vars.iter() {
            let var_type = btf.borrow_btf().type_by_id(var.type_id);
            let data_slice =
                &rodata_bin[var.offset as usize..var.offset as usize + var.sz as usize];
            println!("Var {}->{}, received data: {:?}", var, var_type, data_slice);
            let should_be = match var_type.name() {
                "fmt2" => b"abcdefg\0".as_slice(),
                "handle_exec.____fmt" => b"Created %d\n\0",
                s => panic!("Unexpected var name {}", s),
            };
            assert_eq!(data_slice, should_be);
        }
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
        load_section_data_with_skel_value(
            btf,
            &runqlat_json.meta.bpf_skel.data_sections[0],
            &mut buf,
        )
        .unwrap();
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
        load_section_data_with_skel_value(
            btf,
            &runqlat_json.meta.bpf_skel.data_sections[0],
            &mut buf,
        )
        .unwrap();
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
        load_section_data_with_skel_value(
            btf,
            &runqlat_json.meta.bpf_skel.data_sections[0],
            &mut buf,
        )
        .unwrap();
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
        load_section_data_with_skel_value(btf, &sp2_json.meta.bpf_skel.data_sections[0], &mut buf)
            .unwrap();
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
        load_section_data_with_skel_value(btf, &sp2_json.meta.bpf_skel.data_sections[0], &mut buf)
            .unwrap();
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
        load_section_data_with_skel_value(btf, &sp2_json.meta.bpf_skel.data_sections[0], &mut buf)
            .unwrap();
        println!("{:?}", buf);
        assert_eq!(&buf[buf.len() - 4..], &[63, 158, 4, 25]);
    }
}
