use base64::Engine;
use deflate::deflate_bytes_zlib;
use serde::{Deserialize, Serialize};
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
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
// Sample types
pub enum SampleMapType {
    #[serde(rename = "log2_hist")]
    /// print the event data as log2_hist plain text
    Log2Hist,
    #[serde(rename = "linear_hist")]
    /// print the event data as linear hist plain text
    LinearHist,
    #[serde(rename = "default_kv")]
    /// print the event data as key-value format in plain text or json
    DefaultKV,
}

impl Default for SampleMapType {
    fn default() -> Self {
        SampleMapType::DefaultKV
    }
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
    /// TODO: what's this
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
    /// TODO: what's this
    pub link: bool,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Describe a variable in a data section
pub struct DataSectionVariableMeta {
    /// Name of this variable
    pub name: String,
    #[serde(rename = "type")]
    /// Type of this variable
    pub ty: String,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Describe a data section
pub struct DataSectionMeta {
    /// Name of the section
    pub name: String,
    /// Variables in this section
    pub variables: Vec<DataSectionVariableMeta>,
}
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
/// Docs of a bpf skeleton
/// I'm sure you can understand the meaning of the fields without any docs...
pub struct BpfSkelDoc {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub brief: String,
    #[serde(default)]
    pub details: String,
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
    pub bpf_object: Vec<u8>,
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
        use serde_json::Value;
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
#[derive(Deserialize, Serialize, Debug, Clone)]
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
    pub(crate) fn map_unit_default() -> String {
        "(unit)".into()
    }
}

#[cfg(test)]
mod tests;
