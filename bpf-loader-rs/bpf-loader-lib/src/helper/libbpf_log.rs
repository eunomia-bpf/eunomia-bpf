//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::sync::Once;

use libbpf_rs::{set_print, PrintLevel};

static INIT_LIBBPF_LOGGING: Once = Once::new();
const HARMLESS_TC_REATTACH_WARNING: &str =
    "Kernel error message: Exclusivity flag on, cannot modify";

fn should_suppress_libbpf_message(level: PrintLevel, msg: &str) -> bool {
    level == PrintLevel::Warn && msg.contains(HARMLESS_TC_REATTACH_WARNING)
}

fn log_libbpf_message(level: PrintLevel, msg: String) {
    let msg = msg.trim_end();
    if msg.is_empty() || should_suppress_libbpf_message(level, msg) {
        return;
    }

    if level == PrintLevel::Warn {
        log::warn!("{}", msg);
    } else {
        log::info!("{}", msg);
    }
}

pub(crate) fn init_libbpf_logging() {
    INIT_LIBBPF_LOGGING.call_once(|| {
        set_print(Some((PrintLevel::Info, log_libbpf_message)));
    });
}

#[cfg(test)]
mod tests {
    use libbpf_rs::PrintLevel;

    use super::should_suppress_libbpf_message;

    #[test]
    fn suppresses_harmless_tc_reattach_warning() {
        assert!(should_suppress_libbpf_message(
            PrintLevel::Warn,
            "libbpf: Kernel error message: Exclusivity flag on, cannot modify\n"
        ));
    }

    #[test]
    fn keeps_other_libbpf_warnings_visible() {
        assert!(!should_suppress_libbpf_message(
            PrintLevel::Warn,
            "libbpf: Kernel error message: Filter already exists\n"
        ));
    }

    #[test]
    fn does_not_suppress_tc_reattach_warning_at_info_level() {
        assert!(!should_suppress_libbpf_message(
            PrintLevel::Info,
            "libbpf: Kernel error message: Exclusivity flag on, cannot modify\n"
        ));
    }
}
