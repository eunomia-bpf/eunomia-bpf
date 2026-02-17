//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::{bail, Result};
use btf::types::Btf;

use crate::export_event::{data_dumper::json::dump_to_json, CheckedExportedMember};

pub(crate) fn dump_to_string(btf: &Btf, type_id: u32, data: &[u8], out: &mut String) -> Result<()> {
    out.push_str(&match dump_to_json(btf, type_id, data)? {
        // Remove semicolons..
        serde_json::Value::String(s) => s,
        serde_json::Value::Number(v) => v.to_string(),
        t => t.to_string(),
    });
    Ok(())
}

pub(crate) fn dump_to_string_with_checked_types(
    btf: &Btf,
    checked_types: &[CheckedExportedMember],
    data: &[u8],
    out: &mut String,
) -> Result<()> {
    for member in checked_types.iter() {
        if member.output_header_offset > out.len() {
            out.push_str(&" ".repeat(member.output_header_offset - out.len()));
        } else {
            out.push(' ');
        }
        let offset = (member.bit_offset / 8) as usize;
        if member.bit_offset % 8 != 0 {
            bail!(
                "Bit field found in member {}, but it is not supported now",
                member.field_name
            );
        }
        let end = offset.checked_add(member.size).ok_or_else(|| {
            anyhow::anyhow!(
                "Overflow when computing end offset for member {}: offset={}, size={}",
                member.field_name,
                offset,
                member.size
            )
        })?;
        if end > data.len() {
            bail!(
                "Invalid offset or size for member {}: offset={}, size={}, end={}, data_len={}",
                member.field_name,
                offset,
                member.size,
                end,
                data.len()
            );
        }
        dump_to_string(
            btf,
            member.type_id,
            &data[offset..end],
            out,
        )?;
    }
    Ok(())
}
