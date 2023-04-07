use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{
    btf_container::BtfContainer,
    export_event::{
        EventExporterBuilder, EventHandler, ExportFormatType, ExporterInternalImplementation,
    },
    meta::EunomiaObjectMeta,
    tests::get_assets_dir,
};

pub(crate) fn load_triple() -> (Arc<BtfContainer>, Vec<u8>, EunomiaObjectMeta) {
    let assets = get_assets_dir();
    let btf =
        BtfContainer::new_from_binary(&std::fs::read(assets.join("simple_prog.bpf.o")).unwrap())
            .unwrap();
    let bin_data = std::fs::read(assets.join("dumper_test.bin")).unwrap();
    let skel = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets.join("simple_prog.skel.json")).unwrap(),
    )
    .unwrap();
    (Arc::new(btf), bin_data, skel)
}

pub(crate) type RRC<T> = Rc<RefCell<T>>;

mod map_sampling_tests;
mod ring_buf_tests;

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
        .build_for_ringbuf(&skel.export_types[..], btf)
        .unwrap();
    match &exporter.internal_impl {
        ExporterInternalImplementation::RingBufProcessor {
            event_processor, ..
        } => {
            event_processor.handle_event(&bin_data).unwrap();
        }
        _ => panic!("Unexpected internal implementation"),
    };
}
