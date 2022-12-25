use serde::Deserialize;
use serde::Serialize;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonProg {
    #[serde(rename = "bpf_object")]
    pub bpf_object: String,
    #[serde(rename = "bpf_object_size")]
    pub bpf_object_size: i64,
    pub meta: Meta,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    #[serde(rename = "bpf_skel")]
    pub bpf_skel: BpfSkel,
    #[serde(rename = "eunomia_version")]
    pub eunomia_version: String,
    #[serde(rename = "export_types")]
    pub export_types: Vec<ExportType>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BpfSkel {
    #[serde(rename = "data_sections")]
    pub data_sections: Vec<DataSection>,
    pub doc: Doc,
    pub maps: Vec<Map>,
    #[serde(rename = "obj_name")]
    pub obj_name: String,
    pub progs: Vec<Prog>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSection {
    pub name: String,
    pub variables: Vec<Variable>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    pub name: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub description: Option<String>,
    pub cmdarg: Option<Cmdarg>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cmdarg {
    pub default: bool,
    pub long: String,
    pub short: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Doc {
    pub description: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Map {
    pub ident: String,
    pub name: String,
    pub mmaped: Option<bool>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prog {
    pub attach: String,
    pub link: bool,
    pub name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportType {
    pub members: Vec<Member>,
    pub name: String,
    pub size: i64,
    #[serde(rename = "type_id")]
    pub type_id: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub name: String,
    #[serde(rename = "type")]
    pub type_field: String,
}
