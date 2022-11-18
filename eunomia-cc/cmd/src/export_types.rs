use std::fs;

use crate::config::*;
use anyhow::Result;
use regex::Captures;
use regex::Regex;
const _EXPORT_C_TEMPLATE: &'static str = r#"
// do not use this file: auto generated
#include "vmlinux.h"

// make the compiler not ignore event struct
// generate BTF event struct

"#;

const REGEX_STRUCT_PATTREN: &'static str = r#"struct\s+(\w+)\s*\{"#;

// find all structs in event header
pub fn find_all_export_structs(args: &Args) -> Result<Vec<String>> {
    let mut export_structs: Vec<String> = Vec::new();
    let export_struct_header = fs::read_to_string(&args.export_event_header)?;
    let re = Regex::new(REGEX_STRUCT_PATTREN).unwrap();

    for cap in re.captures_iter(&export_struct_header) {
        let struct_name = &cap[1];
        export_structs.push(struct_name.to_string());
    }
    Ok(export_structs)
}

// add  __attribute__((preserve_access_index)) for structs to preserve BTF info
pub fn _add_preserve_access_index(args: &Args) -> Result<String> {
    let export_struct_header = fs::read_to_string(&args.export_event_header)?;
    // skip enum
    let re = Regex::new(r"(enum\s+\w+\s*\{[^\}]*\});").unwrap();
    let result = re.replace_all(&export_struct_header, |caps: &Captures| {
        format!("{} ;", &caps[1])
    });
    let re = Regex::new(r"\};").unwrap();
    let result = re.replace_all(&result, "} __attribute__((preserve_access_index));");
    Ok(result.to_string())
}

pub fn add_unused_ptr_for_structs(args: &Args, file_path: &str) -> Result<()> {
    let export_struct_names = find_all_export_structs(args)?;
    let mut content = fs::read_to_string(file_path)?;

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
        let test_event = include_str!("../test/event.h");
        let re = Regex::new(REGEX_STRUCT_PATTREN).unwrap();
        assert_eq!(&re.captures(test_event).unwrap()[1], "event");
        let test_event = r#"
            struct eventqwrd3 { int x };
            struct event2 { int x };
            typedef struct event3 { int x } event3_t;
        "#;
        for cap in re.captures_iter(test_event) {
            println!("Found match: {}", &cap[1]);
        }
    }
}
