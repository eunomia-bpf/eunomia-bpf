//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::ffi::CStr;

use anyhow::{anyhow, bail, Result};
use btf::types::{
    Btf, BtfArray, BtfComposite, BtfConst, BtfEnum, BtfFloat, BtfInt, BtfIntEncoding, BtfRestrict,
    BtfType, BtfTypedef, BtfVolatile,
};
use log::debug;
use serde_json::{json, Value};

use crate::export_event::CheckedExportedMember;

pub(crate) fn dump_to_json(btf: &Btf, type_id: u32, data: &[u8]) -> Result<Value> {
    let ty = btf
        .types()
        .get(type_id as usize)
        .ok_or_else(|| anyhow!("Invalid type id: {}", type_id))?;
    let range = data;
    debug!(
        "Processing type `{}`, id={}, data_size={},desc=\n{}",
        ty.name(),
        type_id,
        data.len(),
        ty
    );
    match ty {
        BtfType::Int(btf_int) => dump_int(btf_int, range),
        BtfType::Ptr(_) => dump_pointer(range),
        BtfType::Array(arr) => dump_array(btf, arr, type_id, range),
        BtfType::Struct(comp) | BtfType::Union(comp) => dump_composed_type(btf, comp, range),
        BtfType::Enum(btf_enum) => dump_enum(btf_enum, range),
        BtfType::Float(ft) => dump_float(ft, range),
        BtfType::Typedef(BtfTypedef { type_id, .. })
        | BtfType::Volatile(BtfVolatile { type_id })
        | BtfType::Const(BtfConst { type_id })
        | BtfType::Restrict(BtfRestrict { type_id }) => dump_to_json(btf, *type_id, data),

        BtfType::Void => bail!("Void type is not supported in dumping"),
        BtfType::Fwd(_) => bail!("Forawrd is not supported"),

        BtfType::Func(_) => bail!("Func is not supported"),
        BtfType::FuncProto(_) => bail!("FuncProto is not supported"),
        BtfType::Var(_) => bail!("Var is not supported"),
        BtfType::Datasec(_) => bail!("Datasec is not supported"),
        BtfType::DeclTag(_) => bail!("DeclTag is not supported"),
        BtfType::TypeTag(_) => bail!("TypeTag is not supported"),
    }
}

pub(crate) fn dump_to_json_with_checked_types(
    btf: &Btf,
    checked_export_value_member_types: &[CheckedExportedMember],
    data: &[u8],
) -> Result<Value> {
    let mut result = serde_json::Map::new();

    for member in checked_export_value_member_types.iter() {
        result.insert(
            member.meta.name.clone(),
            dump_to_json(
                btf,
                member.type_id,
                &data[(member.bit_offset / 8) as usize
                    ..((member.bit_offset / 8) as usize + member.size)],
            )?,
        );
    }
    Ok(json!(result))
}

pub(crate) fn dump_int(btf_int: &BtfInt, range: &[u8]) -> Result<Value> {
    // Special handle for bools
    if let BtfIntEncoding::Bool = btf_int.encoding {
        Ok(json!(range[0] != 0))
    } else {
        // For other integers, we just return their representations in json
        if range.len() < (btf_int.bits / 8) as usize {
            bail!(
                "Bits are too short, expected {} bits, but {} bits received",
                btf_int.bits,
                range.len() * 8
            );
        }

        let mut result: u128 = 0;
        for i in 0..btf_int.bits / 8 {
            // Everything is little-endian, right?
            // So we constructed an u64 through shiftings
            // Then truncate the corresponding bytes to the type we want
            result |= (range[i as usize] as u128) << (i * 8);
        }
        let result = match (btf_int.bits, btf_int.encoding) {
            (8, BtfIntEncoding::Signed) => json!(result as i8),
            (8, _) => json!(result as u8),
            (16, BtfIntEncoding::Signed) => json!(result as i16),
            (16, _) => json!(result as u16),
            (32, BtfIntEncoding::Signed) => json!(result as i32),
            (32, _) => json!(result as u32),
            (64, BtfIntEncoding::Signed) => json!(result as i64),
            (64, _) => json!(result as u64),
            (128, BtfIntEncoding::Signed) => json!(result as i128),
            #[allow(clippy::unnecessary_cast)]
            (128, _) => json!(result as u128),
            (a, _) => {
                bail!("Unsupported integer length: {} in bits", a);
            }
        };

        Ok(result)
    }
}
//For pointers, we just interprete them as integers
pub(crate) fn dump_pointer(range: &[u8]) -> Result<Value> {
    Ok(if range.len() == 4 {
        json!(u32::from_le_bytes(range[0..4].try_into()?))
    } else {
        json!(u64::from_le_bytes(range[0..8].try_into()?))
    })
}

pub(crate) fn dump_array(btf: &Btf, arr: &BtfArray, type_id: u32, range: &[u8]) -> Result<Value> {
    // For c-strings, return a string; For arrays in other types, return a json array
    let elem_ty = btf.types().get(arr.val_type_id as usize).ok_or_else(|| {
        anyhow!(
            "Invalid element type {} of array {}",
            type_id,
            arr.val_type_id
        )
    })?;
    let is_c_str = elem_ty.name() == "char";
    if is_c_str {
        // Here, this array represents an char[N], which can be interpreted as a string
        let mut last_idx = 0;
        while last_idx < range.len() && range[last_idx] != 0 {
            last_idx += 1;
        }
        let out_str = CStr::from_bytes_with_nul(&range[..=last_idx])?.to_str()?;
        Ok(json!(out_str))
    } else {
        // For non-strings, just create a json array and recursively to fill it
        let mut result: Vec<Value> = vec![];
        let elem_size = btf.get_size_of(arr.val_type_id) as usize;
        for i in 0..arr.nelems as usize {
            result.push(dump_to_json(
                btf,
                arr.val_type_id,
                &range[i * elem_size..(i + 1) * elem_size],
            )?);
        }
        Ok(json!(result))
    }
}

pub(crate) fn dump_composed_type(btf: &Btf, comp: &BtfComposite, range: &[u8]) -> Result<Value> {
    // For structs or unions, construct a json object and fill elements into that
    let mut result = serde_json::Map::new();
    result.insert(
        "__EUNOMIA_TYPE".into(),
        if comp.is_struct {
            "struct".into()
        } else {
            "union".into()
        },
    );
    result.insert("__EUNOMIA_TYPE_NAME".into(), comp.name.into());

    for elem in comp.members.iter() {
        if elem.bit_offset % 8 != 0 {
            bail!(
                "Unsupported bit offset: {} in {}::{} ({})",
                elem.bit_offset,
                elem.name,
                comp.name,
                if comp.is_struct { "struct" } else { "union" },
            );
        }
        if elem.bit_size % 8 != 0 {
            bail!(
                "Unsupported bit size: {} in {}::{} ({})",
                elem.bit_size,
                elem.name,
                comp.name,
                if comp.is_struct { "struct" } else { "union" },
            );
        }
        debug!(
            "Current member: name=`{}`, bit_offset={}, bit_size={}",
            elem.name, elem.bit_offset, elem.bit_size
        );
        let elem_size = btf.get_size_of(elem.type_id);
        result.insert(
            elem.name.into(),
            dump_to_json(
                btf,
                elem.type_id,
                &range[(elem.bit_offset / 8) as usize..(elem.bit_offset / 8 + elem_size) as usize],
            )?,
        );
    }
    Ok(json!(result))
}

pub(crate) fn dump_enum(btf_enum: &BtfEnum, range: &[u8]) -> Result<Value> {
    // For enums, output a string containing its variant name and corresponding value
    let val = match btf_enum.sz {
        1 => i8::from_le_bytes(range.try_into()?) as i32,
        2 => i16::from_le_bytes(range.try_into()?) as i32,
        4 => i32::from_le_bytes(range.try_into()?),
        s => bail!("Unsupported enumeration size: {}", s),
    };
    let mut result = None;
    for variant in btf_enum.values.iter() {
        if variant.value == val {
            result = Some(format!("{}({})", variant.name, variant.value));
            break;
        }
    }
    if let Some(v) = result {
        Ok(json!(v))
    } else {
        Ok(json!(format!("<UNKNOWN_VARIANT>({val})")))
    }
}
pub(crate) fn dump_float(ft: &BtfFloat, range: &[u8]) -> Result<Value> {
    // For floats, just cast them to Number in json
    match ft.sz {
        4 => Ok(json!(f32::from_le_bytes(range.try_into()?))),
        8 => Ok(json!(f64::from_le_bytes(range.try_into()?))),
        s => {
            bail!("Unsupported float size: {}", s);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{get_assets_dir, ExampleTestStruct};
    use btf::types::Btf;
    use object::ElfFile;

    use super::dump_to_json;

    #[test]
    fn test_dump_to_json() {
        let assets_dir = get_assets_dir();
        let elf = std::fs::read(assets_dir.join("simple_prog").join("simple_prog.bpf.o")).unwrap();
        let bin = std::fs::read(assets_dir.join("simple_prog").join("dumper_test.bin")).unwrap();
        let elf: ElfFile = ElfFile::parse(&elf[..]).unwrap();
        let btf = Btf::load(&elf).unwrap();
        // type_id = 2 is the struct we want
        let out_json = dump_to_json(&btf, 2, &bin[..]).unwrap();
        let d: ExampleTestStruct = serde_json::from_value(out_json).unwrap();
        d.test_with_example_data();
    }
}
