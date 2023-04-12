use std::sync::Weak;

use crate::export_event::{
    data_dumper::{
        json::dump_to_json_with_checked_types, plain_text::dump_to_string_with_checked_types,
    },
    EventExporter, ExporterInternalImplementation, InternalSimpleValueEventProcessor,
    ReceivedEventData,
};

use anyhow::{bail, Result};
use chrono::Local;
use log::warn;
use serde_json::json;

use std::fmt::Write;

pub(crate) struct JsonExportEventHandler {
    pub(crate) exporter: Weak<EventExporter>,
}
impl InternalSimpleValueEventProcessor for JsonExportEventHandler {
    fn handle_event(&self, data: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let checked_export_value_member_types = match &exporter.internal_impl {
            ExporterInternalImplementation::RingBufProcessor { checked_types, .. } => checked_types,
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

impl InternalSimpleValueEventProcessor for RawExportEventHandler {
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

impl InternalSimpleValueEventProcessor for PlainStringExportEventHandler {
    fn handle_event(&self, data: &[u8]) -> Result<()> {
        let exporter = self.exporter.upgrade().unwrap();
        let mut outbuf = String::default();
        let now_str = Local::now().format("%H:%M:%S").to_string();
        // SAFETY: It won't fail
        write!(outbuf, "{now_str:<8} ").unwrap();
        let checked_export_value_member_types = match &exporter.internal_impl {
            ExporterInternalImplementation::RingBufProcessor { checked_types, .. } => checked_types,
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
