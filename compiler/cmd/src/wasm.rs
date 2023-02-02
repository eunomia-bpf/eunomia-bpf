use std::fs;

use crate::config::*;
use anyhow::Result;

const _WASM_C_TEMPLATE: &str = r#"
// auto generated. do not edit.
#ifndef EWASM_JSON_INCLUDE_H_
#define EWASM_JSON_INCLUDE_H_
char* program_data = {}
base = {};
#endif
"#;

pub fn pack_object_in_wasm_header(args: &Options) -> Result<()> {
    let json_path = get_output_package_config_path(args);
    let json_str = fs::read_to_string(json_path)?;
    let json = json_str.replace("\"", "\\\"");
    let content = format!(
        r#"
    // auto generated. do not edit.
    #ifndef EWASM_JSON_INCLUDE_H_
    #define EWASM_JSON_INCLUDE_H_
    char* program_data = "{}";
    #endif
    "#,
        json
    );
    let wasm_path = get_wasm_header_path(args);
    fs::write(wasm_path, content)?;
    Ok(())
}
