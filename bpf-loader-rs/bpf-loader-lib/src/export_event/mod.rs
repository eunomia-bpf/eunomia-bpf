//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

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
    meta::{ExportedTypesStructMeta, MapSampleMeta, SampleMapType},
};
use anyhow::{anyhow, bail, Context, Result};
use std::{any::Any, fmt::Display, sync::Arc};

use self::{
    checker::check_export_types_btf,
    event_handlers::{get_plain_text_checked_types_header, key_value, simple_value},
    type_descriptor::{CheckedExportedMember, TypeDescriptor},
};

pub(crate) mod checker;
pub(crate) mod data_dumper;
pub(crate) mod event_handlers;
#[cfg(test)]
mod tests;
/// Contains utilities to describe where to obtain the export type of a map
pub mod type_descriptor;
#[derive(Clone, Copy)]
/// Describe the export format type
pub enum ExportFormatType {
    /// Use human-readable texts to output
    PlainText,
    /// Use machine-readable json to output
    Json,
    /// Only call the callback with raw buffer
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

impl<'a> ReceivedEventData<'a> {
    /// Simply get a &[u8] from this received data, which is the same as the one that the C++ version callback receives
    pub fn trivally_to_plain_bytes(&self) -> &'a [u8] {
        match self {
            ReceivedEventData::Buffer(buf) => buf,
            ReceivedEventData::KeyValueBuffer { value, .. } => value,
            ReceivedEventData::PlainText(txt) => txt.as_bytes(),
            ReceivedEventData::JsonText(txt) => txt.as_bytes(),
        }
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

/// The builder of the EventExporter
pub struct EventExporterBuilder {
    export_format: ExportFormatType,
    export_event_handler: Option<Arc<dyn EventHandler>>,
    user_ctx: Option<Arc<dyn Any>>,
}

impl Default for EventExporterBuilder {
    fn default() -> Self {
        Self {
            export_format: ExportFormatType::PlainText,
            export_event_handler: None,
            user_ctx: None,
        }
    }
}

impl EventExporterBuilder {
    /// Create a default Builder, with export_format defaults to `ExportFormat::PlainText`
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the export format that the ebpf program will export
    pub fn set_export_format(self, fmt: ExportFormatType) -> Self {
        Self {
            export_format: fmt,
            ..self
        }
    }
    /// Set a user-defined event handler callback
    pub fn set_export_event_handler(self, handler: Arc<dyn EventHandler>) -> Self {
        Self {
            export_event_handler: Some(handler),
            ..self
        }
    }
    /// Set the user-defined context
    pub fn set_user_context<T: Any>(self, ctx: T) -> Self {
        Self {
            user_ctx: Some(Arc::new(ctx)),
            ..self
        }
    }
    /// Build an exporter use TypeDescriptor. Which can easily specify the source to obtain the value type
    pub fn build_for_single_value_with_type_descriptor(
        self,
        export_type: TypeDescriptor,
        btf_container: Arc<BtfContainer>,
    ) -> Result<Arc<EventExporter>> {
        let mut checked_exported_members =
            export_type.build_checked_exported_members(btf_container.borrow_btf())?;

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
    /// Build an EventExporter which is suitable for processing value-only data
    /// export_types: The type of the data that kernel program sends. The types will be verified using BTF
    /// btf_container: The BTF information
    pub fn build_for_single_value(
        self,
        export_type: &ExportedTypesStructMeta,
        btf_container: Arc<BtfContainer>,
    ) -> Result<Arc<EventExporter>> {
        let checked_members = check_export_types_btf(export_type, btf_container.borrow_btf())?;
        Self::build_for_single_value_with_type_descriptor(
            self,
            TypeDescriptor::CheckedMembers(checked_members),
            btf_container,
        )
    }
    /// Build an EventExporter, but use TypeDescriptor to indicate where to fetch the value type
    pub fn build_for_key_value_with_type_desc(
        self,
        key_export_type: TypeDescriptor,
        value_export_type: TypeDescriptor,
        sample_config: &MapSampleMeta,
        btf_container: Arc<BtfContainer>,
    ) -> Result<Arc<EventExporter>> {
        let mut checked_key_types =
            key_export_type.build_checked_exported_members(btf_container.borrow_btf())?;
        let mut checked_value_types =
            value_export_type.build_checked_exported_members(btf_container.borrow_btf())?;

        if matches!(self.export_format, ExportFormatType::PlainText)
            && matches!(sample_config.ty, SampleMapType::LinearHist)
        {
            bail!("Linear hist sampling is not supported now");
        }
        Ok(Arc::new_cyclic(move |me| {
            let internal_sample_map_processor: Box<dyn InternalSampleMapProcessor> = match self
                .export_format
            {
                ExportFormatType::PlainText => match sample_config.ty {
                    SampleMapType::Log2Hist => Box::new(key_value::Log2HistExportEventHandler {
                        exporter: me.clone(),
                    }),
                    SampleMapType::StackTrace => Box::new(key_value::StackTraceExportEventHandler {
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
    /// Build an EventExporter to process sampling map
    /// key_type_id: The type id of the map key
    /// value_type_id: The type id of the map value
    /// sample_config: Detailed configuration of the sampling map
    /// export_types: Value types of the map, will be verified
    /// btf_container: The btf information
    pub fn build_for_key_value(
        self,
        key_type_id: u32,
        value_type_id: u32,
        sample_config: &MapSampleMeta,
        export_type: &ExportedTypesStructMeta,
        btf_container: Arc<BtfContainer>,
    ) -> Result<Arc<EventExporter>> {
        let btf = btf_container.borrow_btf();
        let checked_key_types = check_sample_types_btf(btf, key_type_id, None)
            .with_context(|| anyhow!("Failed to check key type"))?;
        let checked_value_types =
            check_sample_types_btf(btf, value_type_id, Some(export_type.clone()))
                .with_context(|| anyhow!("Failed to check value type"))?;
        self.build_for_key_value_with_type_desc(
            TypeDescriptor::CheckedMembers(checked_key_types),
            TypeDescriptor::CheckedMembers(checked_value_types),
            sample_config,
            btf_container,
        )
    }
}
