use std::sync::Weak;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use log::warn;
use serde_json::json;
use std::fmt::Write;

use crate::{
    export_event::{
        data_dumper::{
            json::dump_to_json_with_checked_types,
            plain_text::{dump_to_string, dump_to_string_with_checked_types},
        },
        EventExporter, ExporterInternalImplementation, InternalSampleMapProcessor,
        ReceivedEventData,
    },
    helper::print_log2_hist,
};

pub(crate) struct JsonExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}

impl InternalSampleMapProcessor for JsonExportEventHandler {
    fn handle_event(&self, key_buffer: &[u8], value_buffer: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let btf = exporter.btf_container.borrow_btf();
        let (checked_key_types, checked_value_types) =
            if let ExporterInternalImplementation::KeyValueMapProcessor {
                ref checked_key_types,
                ref checked_value_types,
                ..
            } = exporter.internal_impl
            {
                (checked_key_types, checked_value_types)
            } else {
                bail!("Unexpected internal implemention");
            };
        let key_out = dump_to_json_with_checked_types(btf, checked_key_types, key_buffer)
            .with_context(|| anyhow!("Failed to dump key type to json"))?;
        let value_out = dump_to_json_with_checked_types(btf, checked_value_types, value_buffer)
            .with_context(|| anyhow!("Failed to dump value type to json"))?;
        let final_json = json!({
            "key":key_out,
            "value":value_out
        });
        let out_str = serde_json::to_string(&final_json)
            .with_context(|| anyhow!("Failed to serialize json"))?;
        exporter.dump_data_to_user_callback_or_stdout(ReceivedEventData::JsonText(&out_str));
        Ok(())
    }
}

pub(crate) struct RawExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}

impl InternalSampleMapProcessor for RawExportEventHandler {
    fn handle_event(&self, key_buffer: &[u8], value_buffer: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        if let Some(callback) = exporter.user_export_event_handler.as_ref() {
            callback.handle_event(
                exporter.user_ctx.clone(),
                ReceivedEventData::KeyValueBuffer {
                    key: key_buffer,
                    value: value_buffer,
                },
            );
        } else {
            warn!("Raw map processor expects that a user-provided callback exists, or the data will be dropped");
        }
        Ok(())
    }
}

pub(crate) struct DefaultKVStringExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}

impl InternalSampleMapProcessor for DefaultKVStringExportEventHandler {
    fn handle_event(&self, key_buffer: &[u8], value_buffer: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let btf = exporter.btf_container.borrow_btf();
        let (checked_key_types, checked_value_types) =
            if let ExporterInternalImplementation::KeyValueMapProcessor {
                ref checked_key_types,
                ref checked_value_types,
                ..
            } = exporter.internal_impl
            {
                (checked_key_types, checked_value_types)
            } else {
                bail!("Unexpected internal implemention");
            };
        let now_str = Local::now().format("%H:%M:%S").to_string();
        let mut outbuf = String::new();
        write!(outbuf, "{now_str:<8} ").unwrap();
        write!(
            outbuf,
            "{} {}",
            dump_to_json_with_checked_types(btf, checked_key_types, key_buffer)?,
            dump_to_json_with_checked_types(btf, checked_value_types, value_buffer)?
        )
        .unwrap();
        exporter
            .dump_data_to_user_callback_or_stdout(ReceivedEventData::PlainText(outbuf.as_str()));
        Ok(())
    }
}

pub(crate) struct Log2HistExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}

impl InternalSampleMapProcessor for Log2HistExportEventHandler {
    fn handle_event(&self, key_buffer: &[u8], value_buffer: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let btf = exporter.btf_container.borrow_btf();
        let (checked_key_types, checked_value_types, sample_map_config) =
            if let ExporterInternalImplementation::KeyValueMapProcessor {
                ref checked_key_types,
                ref checked_value_types,
                ref sample_map_config,
                ..
            } = exporter.internal_impl
            {
                (checked_key_types, checked_value_types, sample_map_config)
            } else {
                bail!("Unexpected internal implemention");
            };
        let mut outbuf = String::new();
        write!(outbuf, "key = ").unwrap();
        dump_to_string_with_checked_types(btf, checked_key_types, key_buffer, &mut outbuf)?;
        writeln!(outbuf).unwrap();
        struct SlotsDef {
            offset: u32,
            length_in_u32: u32,
        }
        let mut slots: Option<SlotsDef> = None;

        for member in checked_value_types.iter() {
            let offset = member.bit_offset / 8;
            if member.bit_offset % 8 != 0 {
                bail!("bit fields are not supported now");
            }
            if member.meta.name == "slots" {
                slots = Some(SlotsDef {
                    offset,
                    length_in_u32: (member.size as u32) / 4,
                });
            } else {
                write!(outbuf, "{} = ", member.meta.name).unwrap();
                dump_to_string(
                    btf,
                    member.type_id,
                    &value_buffer[offset as usize..offset as usize + member.size],
                    &mut outbuf,
                )?;
                writeln!(outbuf).unwrap();
            }
        }
        if let Some(SlotsDef {
            offset: slot_offset,
            length_in_u32: slot_size,
        }) = slots
        {
            exporter.dump_data_to_user_callback_or_stdout(ReceivedEventData::PlainText(&outbuf));
            let mut val_buf = vec![];
            for i in 0..slot_size {
                val_buf.push(u32::from_le_bytes(
                    value_buffer
                        [(slot_offset + i * 4) as usize..(slot_offset + (i + 1) * 4) as usize]
                        .try_into()?,
                ))
            }
            outbuf.clear();
            print_log2_hist(&val_buf[..], &sample_map_config.unit, &mut outbuf);
            exporter.dump_data_to_user_callback_or_stdout(ReceivedEventData::PlainText(&outbuf));
        } else {
            bail!("No slots found!");
        }
        Ok(())
    }
}
