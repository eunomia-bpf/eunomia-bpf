use std::{
    cell::RefCell,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use serde::Deserialize;
use serde_json::json;

use crate::{
    export_event::{EventHandler, ExportFormatType, ReceivedEventData},
    meta::ComposedObject,
    tests::get_assets_dir,
};

use super::builder::BpfSkeletonBuilder;

#[test]
fn test_load_rodata_and_bss() {
    let mut skel = serde_json::from_str::<ComposedObject>(
        &std::fs::read_to_string(get_assets_dir().join("simple_prog_3").join("package.json"))
            .unwrap(),
    )
    .unwrap();
    skel.meta.bpf_skel.data_sections[0]
        .variables
        .iter_mut()
        .for_each(|s| {
            if s.name == "const_val_1" {
                s.value = Some(json!(0x12345678))
            } else if s.name == "const_val_2" {
                s.value = Some(json!(1u64 << 50));
            } else if s.name == "const_val_3" {
                s.value = Some(json!("aabbccddeeffgg"));
            }
        });
    skel.meta.bpf_skel.data_sections[1]
        .variables
        .iter_mut()
        .for_each(|s| {
            if s.name == "bss_val_1" {
                s.value = Some(json!(0x12344321))
            } else if s.name == "bss_val_2" {
                s.value = Some(json!(1u64 << 60));
            } else if s.name == "bss_val_3" {
                s.value = Some(json!("112233445566"));
            }
        });

    let bpf_skel = BpfSkeletonBuilder::from_json_package(&skel, None)
        .build()
        .unwrap()
        .load_and_attach()
        .unwrap();
    let data = Rc::new(RefCell::new(String::default()));
    let should_stop = Arc::new(AtomicBool::new(false));
    struct MyEventHandler {
        data: Rc<RefCell<String>>,
        should_stop: Arc<AtomicBool>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<std::sync::Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                ReceivedEventData::JsonText(s) => {
                    self.data.replace(s.to_string());
                    self.should_stop.store(true, Ordering::Relaxed)
                }
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let handle = bpf_skel.create_poll_handle();
    {
        let should_stop = should_stop.clone();
        thread::spawn(move || {
            while !should_stop.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }
            handle.terminate();
        });
    }
    bpf_skel
        .wait_and_poll_to_handler(
            ExportFormatType::Json,
            Some(Arc::new(MyEventHandler {
                data: data.clone(),
                should_stop,
            })),
            None,
        )
        .unwrap();
    let inner_data = data.borrow().to_owned();

    #[derive(Deserialize)]
    struct RecvData {
        val_1: i32,
        val_2: u64,
        val_3: String,
        val_4: i32,
        val_5: u64,
        val_6: String,
    }
    let recv_data = serde_json::from_str::<RecvData>(&inner_data).unwrap();
    println!("{}", inner_data);
    assert_eq!(recv_data.val_1, 0x12345678);
    assert_eq!(recv_data.val_2, 1u64 << 50);
    assert_eq!(recv_data.val_3, "aabbccddeeffgg");
    assert_eq!(recv_data.val_4, 0x12344321);
    assert_eq!(recv_data.val_5, 1u64 << 60);
    assert_eq!(recv_data.val_6, "112233445566");
}
