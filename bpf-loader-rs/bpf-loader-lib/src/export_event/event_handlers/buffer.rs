//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::sync::Weak;

use crate::{
    export_event::{
        data_dumper::{
            json::dump_to_json_with_checked_types, plain_text::dump_to_string_with_checked_types,
        },
        EventExporter, ExporterInternalImplementation, InternalBufferValueEventProcessor,
        ReceivedEventData,
    },
    meta::StackTraceFieldMapping,
};

use anyhow::{anyhow, bail, Context, Result};
use blazesym::{
    symbolize::{Kernel, Process, Source, Symbolizer},
    Addr,
};
use chrono::Local;
use log::{debug, warn};
use serde_json::json;

use std::fmt::Write;

pub(crate) struct JsonExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}
impl InternalBufferValueEventProcessor for JsonExportEventHandler {
    fn handle_event(&self, data: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let checked_export_value_member_types = match &exporter.internal_impl {
            ExporterInternalImplementation::BufferValueProcessor { checked_types, .. } => {
                checked_types
            }
            _ => bail!("Unexpected"),
        };

        let result = dump_to_json_with_checked_types(
            exporter.btf_container.borrow_btf(),
            checked_export_value_member_types,
            data,
        )?;
        let str_out = serde_json::to_string(&json!(result))?;
        if let Some(v) = exporter.user_export_event_handler.as_ref() {
            v.handle_event(
                exporter.user_ctx.clone(),
                ReceivedEventData::JsonText(&str_out),
            );
        } else {
            println!("{str_out}");
        }
        Ok(())
    }
}
pub(crate) struct RawExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}

impl InternalBufferValueEventProcessor for RawExportEventHandler {
    fn handle_event(&self, data: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        if let Some(v) = exporter.user_export_event_handler.as_ref() {
            v.handle_event(exporter.user_ctx.clone(), ReceivedEventData::Buffer(data));
        } else {
            warn!("Raw export event handler expects that user provide an event handler. If not provided, the exported data will be dropped");
        }
        Ok(())
    }
}

pub(crate) struct PlainStringExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}

impl InternalBufferValueEventProcessor for PlainStringExportEventHandler {
    fn handle_event(&self, data: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let mut outbuf = String::default();
        let now_str = Local::now().format("%H:%M:%S").to_string();
        // SAFETY: It won't fail
        write!(outbuf, "{now_str:<8} ").unwrap();
        let checked_export_value_member_types = match &exporter.internal_impl {
            ExporterInternalImplementation::BufferValueProcessor { checked_types, .. } => {
                checked_types
            }
            _ => bail!("Unexpected"),
        };

        dump_to_string_with_checked_types(
            exporter.btf_container.borrow_btf(),
            checked_export_value_member_types,
            data,
            &mut outbuf,
        )?;
        exporter
            .dump_data_to_user_callback_or_stdout(ReceivedEventData::PlainText(outbuf.as_str()));

        Ok(())
    }
}

/// Check whether the field mapping is correct
/// - Mapped field names are available
/// - Mapped fields are expected to have correct type
/// A correct definition should be like
/// ```c
/// typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
/// struct stacktrace_event {
///     __u32 pid;
///     __u32 cpu_id;
///     char comm[TASK_COMM_LEN];
///     __s32 kstack_sz;
///     __s32 ustack_sz;
///     stack_trace_t kstack;
///     stack_trace_t ustack;
/// };
pub(crate) struct PlainTextStackTraceExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
    pub(crate) field_mapping: StackTraceFieldMapping,
    pub(crate) with_symbols: bool,
}

macro_rules! extract_field {
    ($map:expr, $main_json: expr, $name: literal, $out_type: ty) => {{
        let map = &$map.as_ref().map(|s| s.as_str());
        let v = map.unwrap_or($name);
        if let Some(v) = $main_json.get(v) {
            use anyhow::Context;
            match serde_json::from_value::<$out_type>(v.clone()).with_context(|| {
                anyhow::anyhow!("Field `{}` (mapping `{}`) has unexpected type", $name, v)
            }) {
                Ok(v) => anyhow::Result::Ok(v),
                Err(e) => Err(e),
            }
        } else {
            anyhow::Result::Err(anyhow::anyhow!(
                "Field mapping `{}` not found in the output JSON",
                v
            ))
        }
    }};
}

impl InternalBufferValueEventProcessor for PlainTextStackTraceExportEventHandler {
    fn handle_event(&self, data: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let checked_export_value_member_types = match &exporter.internal_impl {
            ExporterInternalImplementation::BufferValueProcessor { checked_types, .. } => {
                checked_types
            }
            _ => bail!("Unexpected"),
        };

        let result = dump_to_json_with_checked_types(
            exporter.btf_container.borrow_btf(),
            checked_export_value_member_types,
            data,
        )?;
        let pid = extract_field!(self.field_mapping.pid, result, "pid", u32)?;
        let cpu_id = extract_field!(self.field_mapping.cpu_id, result, "cpu_id", u32)?;
        let comm = extract_field!(self.field_mapping.comm, result, "comm", String)?;
        // Their units are bytes, not quadwords
        let mut kstack_sz = extract_field!(self.field_mapping.kstack_sz, result, "kstack_sz", i32)?;
        let mut ustack_sz = extract_field!(self.field_mapping.ustack_sz, result, "ustack_sz", i32)?;
        let mut kstack = extract_field!(self.field_mapping.kstack, result, "kstack", Vec<u64>)?;
        let mut ustack = extract_field!(self.field_mapping.ustack, result, "ustack", Vec<u64>)?;

        kstack_sz /= std::mem::size_of::<u64>() as i32;
        ustack_sz /= std::mem::size_of::<u64>() as i32;

        let mut out_str = String::default();

        if kstack_sz <= 0 && ustack_sz <= 0 {
            debug!("No stack info available. skipping");
            return Ok(());
        }
        writeln!(out_str, "COMM: {} (pid={}) @ CPU {}", comm, pid, cpu_id).unwrap();

        let print_stack = |out: &mut String, src: Source, stack: &[u64]| -> Result<()> {
            if self.with_symbols {
                print_stack_trace(out, src, stack)
            } else {
                print_stack_trace_without_symbol(out, stack);
                Ok(())
            }
        };

        if kstack_sz > 0 {
            kstack.resize(kstack_sz as _, 0);
            writeln!(out_str, "Kernel:").unwrap();
            print_stack(&mut out_str, Source::Kernel(Kernel::default()), &kstack)
                .with_context(|| anyhow!("Failed to generate kernel stack trace"))?;
        } else {
            writeln!(out_str, "No Kernel Stack").unwrap();
        }

        if ustack_sz > 0 {
            ustack.resize(ustack_sz as _, 0);
            writeln!(out_str, "Userspace:").unwrap();
            print_stack(
                &mut out_str,
                Source::Process(Process::new(pid.into())),
                &ustack,
            )
            .with_context(|| anyhow!("Failed to generate userspace stack trace"))?;
        } else {
            writeln!(out_str, "No Userspace Stack").unwrap();
        }

        if let Some(v) = exporter.user_export_event_handler.as_ref() {
            v.handle_event(
                exporter.user_ctx.clone(),
                ReceivedEventData::PlainText(&out_str),
            );
        } else {
            println!("{out_str}");
        }
        Ok(())
    }
}

fn print_stack_trace_without_symbol(out: &mut String, stack: &[u64]) {
    for (i, item) in stack.iter().enumerate() {
        writeln!(out, "  {} [<{:016x}>]", i, item).unwrap();
    }
}

fn print_stack_trace(out: &mut String, src: Source, stack: &[u64]) -> Result<()> {
    let addrs = stack.iter().map(|v| (*v) as Addr).collect::<Vec<_>>();
    let symlist = match Symbolizer::new().symbolize(&src, &addrs) {
        Ok(v) => v,
        Err(e) => {
            debug!(
                "Failed to symbolize stack trace for source {:?},\
                 will directly print addresses\nError:\n{:?}",
                src, e
            );
            print_stack_trace_without_symbol(out, stack);
            return Ok(());
        }
    };
    for i in 0..addrs.len() {
        if symlist.len() <= i || symlist[i].is_empty() {
            writeln!(out, "  {} [<{:016x}>]", i, addrs[i]).unwrap();
            continue;
        }
        let curr = &symlist[i];
        if curr.len() == 1 {
            let sym = &curr[0];
            if sym.path.to_string_lossy().len() > 0 {
                writeln!(
                    out,
                    "  {} [<{:016x}>] {}+0x{:x} {:?}:{}",
                    i,
                    addrs[i],
                    sym.symbol,
                    addrs[i] - sym.addr,
                    sym.path,
                    sym.line
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "  {} [<{:016x}>] {}+0x{:x}",
                    i,
                    addrs[i],
                    sym.symbol,
                    addrs[i] - sym.addr,
                )
                .unwrap();
            }
        } else {
            writeln!(out, "  {} [<{:016x}>]", i, addrs[i]).unwrap();
            for ent in curr.iter() {
                if ent.path.to_string_lossy().len() > 0 {
                    writeln!(
                        out,
                        "        {}+0x{:x} {:?}:{}",
                        ent.symbol,
                        addrs[i] - ent.addr,
                        ent.path,
                        ent.line
                    )
                    .unwrap();
                } else {
                    writeln!(out, "        {}+0x{:x}", ent.symbol, addrs[i] - ent.addr).unwrap();
                }
            }
        }
    }
    Ok(())
}
