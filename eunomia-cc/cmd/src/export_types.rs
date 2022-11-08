use std::fs;

use crate::config::*;
use anyhow::Result;
use regex::Regex;
const EXPORT_C_TEMPLATE: &'static str = r#"
// do not use this file: auto generated
#include "vmlinux.h"

// make the compiler not ignore event struct
// generate BTF event struct

"#;

const REGEX_STRUCT_PATTREN: &'static str = r#"struct\s+(\w+)\s*\{"#;

pub fn create_tmp_export_c_file(args: &Args, path: &str) -> Result<()> {
    // use the struct in event.h to generate the export c file
    let mut export_struct_file: String = EXPORT_C_TEMPLATE.into();
    let export_struct_header = fs::read_to_string(&args.export_event_header)?;
    let re = Regex::new(REGEX_STRUCT_PATTREN).unwrap();

    export_struct_file += &format!(
        "#include \"{}\"\n\n",
        fs::canonicalize(&args.export_event_header)?
            .to_str()
            .unwrap()
    );

    for cap in re.captures_iter(&export_struct_header) {
        let struct_name = &cap[1];
        export_struct_file += &format!(
            "const volatile struct {} * __eunomia_dummy_{}_ptr;\n",
            struct_name, struct_name
        );
    }
    fs::write(path, export_struct_file.as_bytes())?;
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
