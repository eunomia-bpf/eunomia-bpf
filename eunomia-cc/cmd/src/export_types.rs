const EXPORT_C_TEMPLATE: &'static str = r#"
// do not use this file: auto generated
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "asm-generic/int-ll64.h"

// make the compiler not ignore event struct
// generate BTF event struct

"#;
