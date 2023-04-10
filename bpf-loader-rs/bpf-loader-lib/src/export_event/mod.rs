//! # Event exporter for bpf-loader-rs
//!
//! ## What does this module do?
//! In a nut shell, this module provides a struct `EventExporter`, which accepts exported data from a ebpf program, verifies the data, then output them to stdout or the user-provided callback function.
//!
//! ## Constructors
//! Usually, ebpf program will export data sampled from the kernel in one of the two ways:
//! - ringbuf
//! - bpf map
//! There are also two constructors for EventExporter, which corresponds to the two ways, `EventExporterBuilder::build_for_ringbuf` and `EventExporterBuilder::build_for_map_sampling`
//!
//! ## What will be produced
//!
//! You can get the data you want in one of the three formats:
//! - Json
//! - PlainText
//! - RawEvent
//!
//! Each time the EventExporter received data from the ebpf program, it will convert the data to the format you want, and call the callback function to acknowledge you the data, or print that to stdout
//! ## Json
//! Convert the received data to a JsonValue. With the help of BTF, we can know at which offset exists which type of data. So It's ok to construct a JsonValue representing the type we want to see. The JsonValue will be passed to the callback in string format, or printed to stdout if you don't want to provide a callback
//!
//! ## PlainText
//! It's similar to JSON, except that it's not structured, only human readable texts
//!
//! ## RawEvent
//! It will call the callback with the original data received from ebpf program. If no callback was provided, it will do nothing.

use crate::{
    btf_container::BtfContainer,
    export_event::checker::check_sample_types_btf,
    meta::{ExportedTypesStructMemberMeta, ExportedTypesStructMeta, MapSampleMeta, SampleMapType},
};
use anyhow::{anyhow, bail, Context, Result};
use log::warn;
use std::{any::Any, fmt::Display, sync::Arc};

use self::{
    checker::check_export_types_btf,
    event_handlers::{get_plain_text_checked_types_header, key_value, simple_value},
};

pub(crate) mod checker;
pub mod data_dumper;
pub mod event_handlers;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
/// Describe the export format type
pub enum ExportFormatType {
    PlainText,
    Json,
    RawEvent,
}
#[derive(Debug)]
/// Represents a sample data that the user will receive
pub enum ReceivedEventData<'a> {
    /// Raw buffer. will be used on simple value sampling pairing with `ExportFormatType::RawEvent`
    Buffer(&'a [u8]),
    /// KeyValue Buffer. will be used on key-value sampling pairing with ` ExportFormatType::RawEvent`
    KeyValueBuffer {
        key: &'a [u8],
        value: &'a [u8],
    },
    // Plain string. will be used on ` ExportFormatType::PlainText`
    PlainText(&'a str),
    // Json string. Will be used on `ExportFormatType::Json`
    JsonText(&'a str),
}
impl<'a> Display for ReceivedEventData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceivedEventData::Buffer(b) => {
                write!(f, "{b:?}")?;
            }
            ReceivedEventData::KeyValueBuffer { key, value } => {
                write!(f, "key: {key:?} value: {value:?}")?;
            }
            ReceivedEventData::PlainText(s) | ReceivedEventData::JsonText(s) => {
                write!(f, "{s}")?;
            }
        }
        Ok(())
    }
}
/// A handler to receive events provided by ebpf kernel program
pub trait EventHandler {
    fn handle_event(&self, context: Option<Arc<dyn Any>>, data: ReceivedEventData);
}

pub(crate) enum ExporterInternalImplementation {
    RingBufProcessor {
        /// internal handler to process export data to a given format
        event_processor: Box<dyn InternalSimpleValueEventProcessor>,
        /// exported value types
        checked_types: Vec<CheckedExportedMember>,
    },
    KeyValueMapProcessor {
        /// internal handler to sample map data to a given format
        event_processor: Box<dyn InternalSampleMapProcessor>,
        /// export map key types meta data
        checked_key_types: Vec<CheckedExportedMember>,
        /// export map value types meta data
        checked_value_types: Vec<CheckedExportedMember>,
        /// Config of the sampling map
        sample_map_config: MapSampleMeta,
    },
}

/// dump export event in user space
pub struct EventExporter {
    /// user defined handler to process export data
    pub(crate) user_export_event_handler: Option<Arc<dyn EventHandler>>,
    pub(crate) internal_impl: ExporterInternalImplementation,
    /// user-defined context
    pub(crate) user_ctx: Option<Arc<dyn Any>>,
    pub(crate) btf_container: Arc<BtfContainer>,
}

impl EventExporter {
    pub(crate) fn dump_data_to_user_callback_or_stdout(&self, data: ReceivedEventData) {
        dump_data_to_user_callback_or_stdout(
            self.user_export_event_handler.clone(),
            self.user_ctx.clone(),
            data,
        );
    }
}
pub(crate) fn dump_data_to_user_callback_or_stdout(
    user_export_event_handler: Option<Arc<dyn EventHandler>>,
    user_ctx: Option<Arc<dyn Any>>,
    data: ReceivedEventData,
) {
    if let Some(callback) = user_export_event_handler.as_ref() {
        callback.handle_event(user_ctx, data);
    } else {
        println!("{data}");
    }
}
pub(crate) trait InternalSimpleValueEventProcessor {
    fn handle_event(&self, data: &[u8]) -> Result<()>;
}

pub(crate) trait InternalSampleMapProcessor {
    fn handle_event(&self, key_buffer: &[u8], value_buffer: &[u8]) -> Result<()>;
}
#[derive(Debug, Clone)]
pub(crate) struct CheckedExportedMember {
    pub(crate) meta: ExportedTypesStructMemberMeta,
    pub(crate) type_id: u32,
    pub(crate) bit_offset: u32,
    pub(crate) size: usize,
    #[allow(unused)]
    pub(crate) bit_size: u32,
    pub(crate) output_header_offset: usize,
}

pub struct EventExporterBuilder {
    export_format: ExportFormatType,
    export_event_handler: Option<Arc<dyn EventHandler>>,
    user_ctx: Option<Arc<dyn Any>>,
}

impl Default for EventExporterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventExporterBuilder {
    pub fn new() -> Self {
        Self {
            export_format: ExportFormatType::PlainText,
            export_event_handler: None,
            user_ctx: None,
        }
    }
    pub fn set_export_format(self, fmt: ExportFormatType) -> Self {
        Self {
            export_format: fmt,
            ..self
        }
    }
    pub fn set_export_event_handler(self, handler: Arc<dyn EventHandler>) -> Self {
        Self {
            export_event_handler: Some(handler),
            ..self
        }
    }
    pub fn set_user_context<T: Any>(self, ctx: T) -> Self {
        Self {
            user_ctx: Some(Arc::new(ctx)),
            ..self
        }
    }
    /// Build an EventExporter which is suitable for processing ringbuf data
    /// export_types: The type of the data that kernel program sends. Currently there can only be one type. The types will be verified using BTF
    /// btf_container: The BTF information
    pub fn build_for_ringbuf(
        self,
        export_types: &[ExportedTypesStructMeta],
        btf_container: Arc<BtfContainer>,
    ) -> Result<Arc<EventExporter>> {
        if export_types.is_empty() {
            bail!("No export types found");
        }
        if export_types.len() > 1 {
            warn!("Warning: mutiple export types not supported now. use the first struct as output event.");
        }
        let mut checked_exported_members =
            check_export_types_btf(&export_types[0], btf_container.borrow_btf())?;

        Ok(Arc::new_cyclic(move |me| {
            let internal_event_processor: Box<dyn InternalSimpleValueEventProcessor> =
                match self.export_format {
                    ExportFormatType::Json => Box::new(simple_value::JsonExportEventHandler {
                        exporter: me.clone(),
                    }),
                    ExportFormatType::PlainText => {
                        let header = get_plain_text_checked_types_header(
                            &mut checked_exported_members,
                            "TIME     ",
                        );
                        dump_data_to_user_callback_or_stdout(
                            self.export_event_handler.clone(),
                            self.user_ctx.clone(),
                            ReceivedEventData::PlainText(header.as_str()),
                        );
                        Box::new(simple_value::PlainStringExportEventHandler {
                            exporter: me.clone(),
                        })
                    }
                    ExportFormatType::RawEvent => Box::new(simple_value::RawExportEventHandler {
                        exporter: me.clone(),
                    }),
                };
            EventExporter {
                // format_type: self.export_format,
                user_export_event_handler: self.export_event_handler,
                user_ctx: self.user_ctx,
                btf_container,
                internal_impl: ExporterInternalImplementation::RingBufProcessor {
                    event_processor: internal_event_processor,
                    checked_types: checked_exported_members,
                },
            }
        }))
    }
    /// Build an EventExporter to process sampling map
    /// key_type_id: The type id of the map key
    /// value_type_id: The type id of the map value
    /// sample_config: Detailed configuration of the sampling map
    /// export_types: Value types of the map, will be verified
    /// btf_container: The btf information
    pub fn build_for_map_sampling(
        self,
        key_type_id: u32,
        value_type_id: u32,
        sample_config: &MapSampleMeta,
        export_types: &[ExportedTypesStructMeta],
        btf_container: Arc<BtfContainer>,
    ) -> Result<Arc<EventExporter>> {
        if export_types.len() > 1 {
            warn!("Warning: mutiple export types not supported now. use the first struct as output event.");
        }
        let btf = btf_container.borrow_btf();
        let member = if export_types.len() == 1 {
            Some(&export_types[0])
        } else {
            None
        };
        let mut checked_key_types = check_sample_types_btf(btf, key_type_id, None)
            .with_context(|| anyhow!("Failed to check key type"))?;
        let mut checked_value_types = check_sample_types_btf(btf, value_type_id, member.cloned())
            .with_context(|| anyhow!("Failed to check value type"))?;
        if let ExportFormatType::PlainText = self.export_format {
            if let SampleMapType::LinearHist = sample_config.ty {
                bail!("Linear hist sampling is not supported now");
            }
        }
        Ok(Arc::new_cyclic(move |me| {
            let internal_sample_map_processor: Box<dyn InternalSampleMapProcessor> = match self
                .export_format
            {
                ExportFormatType::PlainText => match sample_config.ty {
                    SampleMapType::Log2Hist => Box::new(key_value::Log2HistExportEventHandler {
                        exporter: me.clone(),
                    }),
                    SampleMapType::DefaultKV => {
                        let header = String::from("TIME     ");
                        let header =
                            get_plain_text_checked_types_header(&mut checked_key_types, header);
                        let header =
                            get_plain_text_checked_types_header(&mut checked_value_types, header);
                        dump_data_to_user_callback_or_stdout(
                            self.export_event_handler.clone(),
                            self.user_ctx.clone(),
                            ReceivedEventData::PlainText(header.as_str()),
                        );
                        Box::new(key_value::DefaultKVStringExportEventHandler {
                            exporter: me.clone(),
                        })
                    }
                    SampleMapType::LinearHist => unreachable!(),
                },
                ExportFormatType::Json => Box::new(key_value::JsonExportEventHandler {
                    exporter: me.clone(),
                }),
                ExportFormatType::RawEvent => Box::new(key_value::RawExportEventHandler {
                    exporter: me.clone(),
                }),
            };
            EventExporter {
                user_export_event_handler: self.export_event_handler,
                internal_impl: ExporterInternalImplementation::KeyValueMapProcessor {
                    event_processor: internal_sample_map_processor,
                    checked_key_types,
                    checked_value_types,
                    sample_map_config: sample_config.clone(),
                },
                user_ctx: self.user_ctx,
                btf_container,
            }
        }))
    }
}
