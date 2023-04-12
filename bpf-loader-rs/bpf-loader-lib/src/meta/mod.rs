//! # bpf-loader-meta
//!
//! Here are metadata types used for deserilizing JSON skeletons
//!
//! A valid json skeleton is encoded using one of the two types:
//! - `EunomiaObjectMeta`
//! - `ComposedObject`
//!
//! In fact, the second one is `EunomiaObjectMeta` + ELF binary. So in another words, they are same
//!
//! ## EunomiaObjectMeta
//! Two fields need extra explanation:
//!
//! ### `export_types` : `Vec<ExportedTypesStructMeta>`
//!
//! Here describes the types (usually a struct) of the data that this ebpf program exported to the userspace program. The types described here will be verified using BTF, and used to format the output the ebpf program gives, and passed to the user-callback or stdout. Due to a strange limitation, each program can only have one export types in the `Vec`
//!
//! ### `bpf_skel`: `BpfSkeletonMeta`
//!
//! Will be explained in the next words.
//!
//! ## BpfSkeletonMeta
//!
//! This struct describes the skeleton of an ebpf object.
//! - `data_sections`: Describes `.rodata` and `.bss` sections, and variables in that
//! - `maps`: Describes map declarations that are used in this ebpf object.
//! - `progs`: Describes ebpf programs (functions) in this ebpf object
//! - `obj_name`: The name of this ebpf object
//! - `doc`: Docs, will be used to generate command line parser
//!
//! ## DataSectionMeta
//!
//! Describes a data section, and variables declared in it.
//!
//! ## DataSectionVariableMeta
//!
//! Describes a variable in the corresponding data section.
//!
//! - `name`: The name of this variable
//! - `ty`: The C type of this variable
//! - `value`: The default value of this variable. If not provided and not filled by command line parser, `bpf-loader` will fill the variable with zero bytes
//! - `description`: The description of the variable. Will be used to generate command line parser
//! - `cmdarg`: Detailed configuration on the command line argument of this variable
//!
//! ## VariableCommandArgument
//!
//! Describes the detailed configuration of this variable's command line argument.
//!
//! - `default`: The default value of this command line argument
//! - `long`: The long name of this argument
//! - `short`: The short name of this argument, in one char.
//!
//! ## MapMeta
//!
//! Describes an eBPF map
//!
//! ## ProgMeta
//!
//! Describes an eBPF program

use base64::Engine;
use deflate::deflate_bytes_zlib;
use libbpf_rs::libbpf_sys::{BPF_TC_CUSTOM, BPF_TC_EGRESS, BPF_TC_INGRESS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::DefaultOnNull;
/// Describe a struct member in an exported type
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ExportedTypesStructMemberMeta {
    /// The name of the member
    pub name: String,
    #[serde(rename = "type")]
    /// The type of the member
    pub ty: String,
}

/// Describe an exported struct
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ExportedTypesStructMeta {
    /// Name of the struct
    pub name: String,
    /// Members of the struct
    pub members: Vec<ExportedTypesStructMemberMeta>,
    /// Size of the struct
    pub size: u32,
    /// Btf type id of the struct
    pub type_id: u32,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Default)]
/// Sample types
pub enum SampleMapType {
    #[serde(rename = "log2_hist")]
    /// print the event data as log2_hist plain text
    Log2Hist,
    #[serde(rename = "linear_hist")]
    /// print the event data as linear hist plain text
    LinearHist,
    #[serde(rename = "default_kv")]
    #[default]
    /// print the event data as key-value format in plain text or json
    DefaultKV,
}

/// Extra info for a map which will be used for sampling
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct MapSampleMeta {
    /// Sample interval, in milliseconds
    pub interval: usize,
    /// type of the map
    #[serde(rename = "type", default)]
    pub ty: SampleMapType,
    /// Unit when printing hists
    #[serde(default = "default_helpers::map_unit_default")]
    pub unit: String,
    /// Whether to clean up the map after sampling done
    #[serde(default = "default_helpers::default_bool::<false>")]
    pub clear_map: bool,
}

/// Describe a map
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct MapMeta {
    /// Name of the map
    pub name: String,
    /// TODO: get to know what's this
    pub ident: String,
    /// If the value of this map will be used to describe a data section
    #[serde(default = "default_helpers::default_bool::<false>")]
    pub mmaped: bool,
    /// Extra info if this map will be used for sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample: Option<MapSampleMeta>,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Describe the meta of a bpf program
pub struct ProgMeta {
    /// name of this bpf program
    pub name: String,
    /// Attach point of this program
    pub attach: String,
    /// Whether the attaching of this program will generate a bpf_link
    pub link: bool,
    #[serde(flatten)]
    /// Other fields
    pub others: Value,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Extra fields in prog meta for TC programs
pub struct TCProgExtraMeta {
    #[serde(default)]
    /// TC Hook point
    pub tchook: TCHook,
    #[serde(default)]
    /// TC Hook options
    pub tcopts: TCOpts,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// TC Hook options
pub struct TCHook {
    #[serde(default = "default_helpers::default_i32::<1>")]
    /// Which interface to hook
    pub ifindex: i32,
    #[serde(default)]
    /// Hook point
    pub attach_point: TCAttachPoint,
}
impl Default for TCHook {
    fn default() -> Self {
        Self {
            ifindex: 1,
            attach_point: TCAttachPoint::default(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// TC attach point options
pub enum TCAttachPoint {
    #[serde(rename = "BPF_TC_INGRESS")]
    Ingress,
    #[serde(rename = "BPF_TC_EGRESS")]
    Egress,
    #[serde(rename = "BPF_TC_CUSTOM")]
    Custom,
}
impl Default for TCAttachPoint {
    fn default() -> Self {
        Self::Ingress
    }
}

impl TCAttachPoint {
    /// Get the BPF_TC_XXX values for this enum
    pub fn to_value(&self) -> u32 {
        match self {
            TCAttachPoint::Ingress => BPF_TC_INGRESS,
            TCAttachPoint::Egress => BPF_TC_EGRESS,
            TCAttachPoint::Custom => BPF_TC_CUSTOM,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Options for TC program
pub struct TCOpts {
    #[serde(default = "default_helpers::default_u32::<1>")]
    ///
    pub handle: u32,
    #[serde(default = "default_helpers::default_u32::<1>")]
    ///
    pub priority: u32,
}
impl Default for TCOpts {
    fn default() -> Self {
        Self {
            handle: 1,
            priority: 1,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Default)]
/// The command line argument that can be used to retrive the value of this variable
pub struct VariableCommandArgument {
    #[serde(default)]
    /// The default value of this option
    pub default: Option<Value>,
    /// The long name of this. If not provided, will use the variable name
    pub long: Option<String>,
    /// The short name of this
    pub short: Option<String>,
    /// The help string of this option. If not provided, will use the description
    pub help: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Describe a variable in a data section
pub struct DataSectionVariableMeta {
    /// Name of this variable
    pub name: String,
    #[serde(rename = "type")]
    /// Type of this variable
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Value of this variable. This will be filled into the initial value of the corresponding map
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Description of this variable. Will be used to display in generated command arguments
    pub description: Option<String>,
    #[serde(default)]
    /// The command line argument to produce this variable
    pub cmdarg: VariableCommandArgument,
    #[serde(flatten)]
    /// Other fields
    pub others: Value,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Describe a data section
pub struct DataSectionMeta {
    /// Name of the section
    pub name: String,
    /// Variables in this section
    pub variables: Vec<DataSectionVariableMeta>,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Default)]
/// Docs of a bpf skeleton
/// I'm sure you can understand the meaning of the fields without any docs...
/// UPD: I've forgotten deep source..
pub struct BpfSkelDoc {
    ///
    pub version: Option<String>,
    ///
    pub brief: Option<String>,
    ///
    pub details: Option<String>,
    ///
    pub description: Option<String>,
}
#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Describe a bpf skeleton elf
pub struct BpfSkeletonMeta {
    /// Data sections in this elf
    pub data_sections: Vec<DataSectionMeta>,
    /// Maps this program will use
    pub maps: Vec<MapMeta>,
    #[serde_as(deserialize_as = "DefaultOnNull")]
    /// bpf programs in this object file
    pub progs: Vec<ProgMeta>,
    /// Object file name
    pub obj_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Documents
    pub doc: Option<BpfSkelDoc>,
}
impl BpfSkeletonMeta {
    /// Find a map by its ident
    pub fn find_map_by_ident(&self, ident: impl AsRef<str>) -> Option<&MapMeta> {
        let str_ref = ident.as_ref();
        self.maps.iter().find(|s| s.ident == str_ref)
    }
}

/// global meta data config
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct EunomiaObjectMeta {
    /// Export types
    #[serde(default)]
    pub export_types: Vec<ExportedTypesStructMeta>,
    /// The object skeleton
    pub bpf_skel: BpfSkeletonMeta,

    #[serde(default = "default_helpers::default_usize::<64>")]
    /// perf buffer related config
    pub perf_buffer_pages: usize,
    #[serde(default = "default_helpers::default_usize::<10>")]
    /// perf buffer related config
    pub perf_buffer_time_ms: usize,
    #[serde(default = "default_helpers::default_i32::<100>")]
    /// poll config
    pub poll_timeout_ms: i32,
    #[serde(default = "default_helpers::default_bool::<false>")]
    /// Whether libbpf should print debug info
    /// This will only be apply to libbpf when start running
    pub debug_verbose: bool,
    #[serde(default = "default_helpers::default_bool::<false>")]
    /// print config
    /// print the types and names of export headers
    pub print_header: bool,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ComposedObjectInner {
    pub(crate) bpf_object: String,
    pub(crate) bpf_object_size: usize,
    pub(crate) meta: EunomiaObjectMeta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Describe a full eunomia json(with ebpf object inside)
/// The original json should be like:
/// ```json
/// {
///    "bpf_object": "", // An base64-encoded, zlib deflate-compressed object file
///    "bpf_object_size" : 0 , /// The uncompressed size of the object file, in bytes
///    "meta": {} /// The meta object
/// }
/// ```
pub struct ComposedObject {
    /// The object binary
    pub bpf_object: Vec<u8>,
    /// The meta info
    pub meta: EunomiaObjectMeta,
}

impl Serialize for ComposedObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let bpf_object_size = self.bpf_object.len();
        let compressed = deflate_bytes_zlib(&self.bpf_object);
        let bpf_object_base64 = base64::engine::general_purpose::STANDARD.encode(compressed);

        let json_val = serde_json::to_value(ComposedObjectInner {
            bpf_object: bpf_object_base64,
            bpf_object_size,
            meta: self.meta.clone(),
        })
        .map_err(|e| Error::custom(format!("Failed to serialize: {e}")))?;
        json_val.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ComposedObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let json_val: ComposedObjectInner =
            serde_json::from_value(Value::deserialize(deserializer)?)
                .map_err(|e| Error::custom(format!("Malformed json provided: {e}")))?;
        let base64_decoded = base64::engine::general_purpose::STANDARD
            .decode(&json_val.bpf_object)
            .map_err(|e| Error::custom(format!("Malformed base64: {e}")))?;
        let uncompressed = inflate::inflate_bytes_zlib(&base64_decoded)
            .map_err(|e| Error::custom(format!("Malformed compressed data: {e}")))?;
        if uncompressed.len() != json_val.bpf_object_size {
            return Err(Error::custom(format!(
                "Unmatched size: {} in the json, but {} in the decompressed file",
                json_val.bpf_object_size,
                uncompressed.len()
            )));
        }
        Ok(Self {
            bpf_object: uncompressed,
            meta: json_val.meta,
        })
    }
}

/// Global config to control the behavior of eunomia-bpf
/// TODO: load config from json or config files
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct RunnerConfig {
    /// whether we should print the bpf_printk
    /// from /sys/kernel/debug/tracing/trace_pipe
    #[serde(default = "default_helpers::default_bool::<false>")]
    pub print_kernel_debug: bool,
}

pub(crate) mod default_helpers {
    pub(crate) fn default_bool<const V: bool>() -> bool {
        V
    }
    pub(crate) fn default_usize<const V: usize>() -> usize {
        V
    }
    pub(crate) fn default_i32<const V: i32>() -> i32 {
        V
    }
    pub(crate) fn default_u32<const V: u32>() -> u32 {
        V
    }

    pub(crate) fn map_unit_default() -> String {
        "(unit)".into()
    }
}

/// The builder of `Command`
pub mod arg_builder;
/// A parser that can parse values from command line
pub mod arg_parser;
#[cfg(test)]
mod tests;
