use std::fs;

use crate::config::*;
use anyhow::Result;
use regex::Regex;
const _EXPORT_C_TEMPLATE: &str = r#"
// do not use this file: auto generated
#include "vmlinux.h"

// make the compiler not ignore event struct
// generate BTF event struct

"#;

const REGEX_STRUCT_PATTREN: &str = r#"struct\s+(\w+)\s*\{"#;

// find all structs in event header
pub fn find_all_export_structs(args: &CompileOptions) -> Result<Vec<String>> {
    let mut export_structs: Vec<String> = Vec::new();
    let export_struct_header = fs::read_to_string(&args.export_event_header)?;
    let re = Regex::new(REGEX_STRUCT_PATTREN).unwrap();

    for cap in re.captures_iter(&export_struct_header) {
        let struct_name = &cap[1];
        export_structs.push(struct_name.to_string());
    }
    Ok(export_structs)
}

/// add unused_ptr_for_structs to preserve BTF info
/// optional: add  __attribute__((preserve_access_index)) for structs to preserve BTF info
pub fn add_unused_ptr_for_structs(args: &CompileOptions, file_path: &str) -> Result<()> {
    let export_struct_names = find_all_export_structs(args)?;
    let content = fs::read_to_string(file_path);
    let mut content = match content {
        Ok(content) => content,
        Err(e) => {
            println!("access file {} error: {}", file_path, e);
            return Err(e.into());
        }
    };

    for struct_name in export_struct_names {
        content += &format!(
            "const volatile struct {} * __eunomia_dummy_{}_ptr  __attribute__((unused));\n",
            struct_name, struct_name
        );
    }
    fs::write(file_path, content)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_match_struct() {
        let tmp_file = "/tmp/tmp_test_event.h";
        let arg = CompileOptions {
            export_event_header: tmp_file.to_string(),
            ..Default::default()
        };
        let test_event = r#"
            struct eventqwrd3 { int x };
            struct event2 { int x };
            typedef struct event3 { int x } event3_t;
        "#;
        fs::write(tmp_file, test_event).unwrap();
        let structs = find_all_export_structs(&arg).unwrap();
        assert_eq!(structs.len(), 3);
        assert_eq!(structs[0], "eventqwrd3");
        assert_eq!(structs[1], "event2");
        assert_eq!(structs[2], "event3");
        fs::remove_file(tmp_file).unwrap();
    }

    #[test]
    fn test_add_unused_ptr_for_structs() {
        let tmp_file = "tmp_test_event.h";
        let tmp_source_file = "tmp_test_event.c";
        let arg = CompileOptions {
            export_event_header: tmp_file.to_string(),
            ..Default::default()
        };
        let test_event = r#"
            struct eventqwrd3 { int x };
            struct event2 { int x };
            typedef struct event3 { int x } event3_t;
        "#;
        let test_source_content_res = "const volatile struct eventqwrd3 * __eunomia_dummy_eventqwrd3_ptr  __attribute__((unused));\nconst volatile struct event2 * __eunomia_dummy_event2_ptr  __attribute__((unused));\nconst volatile struct event3 * __eunomia_dummy_event3_ptr  __attribute__((unused));\n";
        fs::write(tmp_file, test_event).unwrap();
        fs::write(tmp_source_file, "").unwrap();
        add_unused_ptr_for_structs(&arg, tmp_source_file).unwrap();
        let content = fs::read_to_string(tmp_source_file).unwrap();
        assert_eq!(test_source_content_res, content);
        fs::remove_file(tmp_file).unwrap();
        fs::remove_file(tmp_source_file).unwrap();
    }
}
