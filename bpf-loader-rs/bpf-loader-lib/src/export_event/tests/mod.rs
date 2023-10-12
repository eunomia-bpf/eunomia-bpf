//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{
    btf_container::BtfContainer,
    export_event::{
        EventExporterBuilder, EventHandler, ExportFormatType, ExporterInternalImplementation,
    },
    meta::{BufferValueInterpreter, EunomiaObjectMeta},
    tests::get_assets_dir,
};

pub(crate) fn load_triple_custom(
    elf: &str,
    dummy_bin: &str,
    skel: &str,
) -> (Arc<BtfContainer>, Vec<u8>, EunomiaObjectMeta) {
    let assets = get_assets_dir();
    let btf = BtfContainer::new_from_binary(&std::fs::read(assets.join(elf)).unwrap()).unwrap();
    let bin_data = std::fs::read(assets.join(dummy_bin)).unwrap();
    let skel = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets.join(skel)).unwrap(),
    )
    .unwrap();
    (Arc::new(btf), bin_data, skel)
}

pub(crate) fn load_triple() -> (Arc<BtfContainer>, Vec<u8>, EunomiaObjectMeta) {
    load_triple_custom(
        "simple_prog/simple_prog.bpf.o",
        "simple_prog/dumper_test.bin",
        "simple_prog/simple_prog.skel.json",
    )
}

pub(crate) type RRC<T> = Rc<RefCell<T>>;

mod buffer_value_tests;
#[cfg(not(feature = "no-load-bpf-tests"))]
mod map_sampling_tests;

#[test]
fn test_user_defined_state() {
    struct UserState {
        val: i32,
    }

    let (btf, bin_data, skel) = load_triple();
    struct MyEventHandler;
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            context: Option<Arc<dyn std::any::Any>>,
            _data: crate::export_event::ReceivedEventData,
        ) {
            let binding = context.unwrap();
            let state = binding.downcast_ref::<UserState>().unwrap();
            assert_eq!(state.val, 0x12345678);
        }
    }
    let exporter = EventExporterBuilder::new()
        .set_export_event_handler(Arc::new(MyEventHandler))
        .set_export_format(ExportFormatType::Json)
        .set_user_context(UserState { val: 0x12345678 })
        .build_for_single_value(
            &skel.export_types[0],
            btf,
            &BufferValueInterpreter::DefaultStruct,
        )
        .unwrap();
    match &exporter.internal_impl {
        ExporterInternalImplementation::BufferValueProcessor {
            event_processor, ..
        } => {
            event_processor.handle_event(&bin_data).unwrap();
        }
        _ => panic!("Unexpected internal implementation"),
    };
}
