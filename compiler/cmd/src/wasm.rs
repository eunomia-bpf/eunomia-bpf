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
    let package_path = args.get_output_package_config_path();
    let package_str = fs::read_to_string(package_path)?;
    let json = package_str.replace('"', "\\\"");
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
    let wasm_path = args.get_wasm_header_path();
    fs::write(wasm_path, content)?;
    Ok(())
}
