use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::Value;

use crate::{
    export_event::{EventHandler, ExportFormatType, ReceivedEventData},
    meta::EunomiaObjectMeta,
    skeleton::{builder::BpfSkeletonBuilder, handle::PollingHandle},
    tests::get_assets_dir,
};

#[test]
fn test_multiple_export_type_with_ringbuf_1() {
    let assets_dir = get_assets_dir().join("multiple_export_ringbuf");
    let bpf_obj = std::fs::read(assets_dir.join("multiple.bpf.o")).unwrap();
    let skel_json = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets_dir.join("multiple.skel.json")).unwrap(),
    )
    .unwrap();

    let data = Arc::new(Mutex::new(Vec::<String>::default()));
    struct MyEventHandler {
        data: Arc<Mutex<Vec<String>>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                ReceivedEventData::JsonText(j) => self.data.lock().unwrap().push(j.to_string()),
                _ => unreachable!(),
            }
        }
    }
    let event_handler = Arc::new(MyEventHandler { data: data.clone() });
    let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
    std::thread::spawn(move || {
        let skel =
            BpfSkeletonBuilder::from_object_meta_and_object_buffer(&skel_json, &bpf_obj, None)
                .build()
                .unwrap()
                .load_and_attach()
                .unwrap();
        tx.send(skel.create_poll_handle()).unwrap();
        skel.wait_and_poll_to_handler(ExportFormatType::Json, Some(event_handler), None)
            .unwrap();
    });
    let handle = rx.recv().unwrap();
    std::process::Command::new("echo")
        .arg("abcd")
        .output()
        .unwrap();
    std::thread::sleep(Duration::from_secs(3));
    println!("{:?}", data.lock().unwrap());
    handle.terminate();
    let mut exec_found = false;
    let mut exit_found = false;
    for item in data.lock().unwrap().iter() {
        let json: Value = serde_json::from_str(item).unwrap();
        let json_obj = json.as_object().unwrap();
        if json_obj.contains_key("filename") {
            exec_found = true;
        }
        if json_obj.contains_key("duration_ns") {
            exit_found = true;
        }
    }
    assert!(exec_found);
    assert!(exit_found);
}

#[test]
fn test_multiple_export_type_with_ringbuf_2() {
    let assets_dir = get_assets_dir().join("multiple_export_ringbuf");
    let bpf_obj = std::fs::read(assets_dir.join("multiple.bpf.o")).unwrap();
    let skel_json = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets_dir.join("multiple.skel.json")).unwrap(),
    )
    .unwrap();

    let data_exec = Arc::new(Mutex::new(Vec::<String>::default()));
    let data_exit = Arc::new(Mutex::new(Vec::<String>::default()));
    struct MyEventHandler {
        data: Arc<Mutex<Vec<String>>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                ReceivedEventData::JsonText(j) => self.data.lock().unwrap().push(j.to_string()),
                _ => unreachable!(),
            }
        }
    }
    let event_handler_exec = Arc::new(MyEventHandler {
        data: data_exec.clone(),
    });
    let event_handler_exit = Arc::new(MyEventHandler {
        data: data_exit.clone(),
    });

    let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
    std::thread::spawn(move || {
        let skel =
            BpfSkeletonBuilder::from_object_meta_and_object_buffer(&skel_json, &bpf_obj, None)
                .build()
                .unwrap()
                .load_and_attach()
                .unwrap();
        tx.send(skel.create_poll_handle()).unwrap();
        skel.wait_and_poll_to_handler_with_multiple_exporter(|name| match name {
            "rb_exec" => Some((ExportFormatType::Json, event_handler_exec.clone(), None)),
            "rb_exit" => Some((ExportFormatType::Json, event_handler_exit.clone(), None)),
            _ => unreachable!(),
        })
        .unwrap();
    });
    let handle = rx.recv().unwrap();
    std::process::Command::new("echo")
        .arg("abcd")
        .output()
        .unwrap();
    std::thread::sleep(Duration::from_secs(3));
    println!("{:?}", data_exec.lock().unwrap());
    handle.terminate();

    assert!(!data_exec.lock().unwrap().is_empty());
    assert!(!data_exit.lock().unwrap().is_empty());
}

#[test]
fn test_multiple_export_type_withring_buf_and_custom_struct() {
    let assets_dir = get_assets_dir().join("multiple_export_ringbuf");
    let bpf_obj = std::fs::read(assets_dir.join("multiple.bpf.o")).unwrap();
    let skel_json = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets_dir.join("multiple-custom-struct.json")).unwrap(),
    )
    .unwrap();

    let data = Arc::new(Mutex::new(Vec::<String>::default()));
    struct MyEventHandler {
        data: Arc<Mutex<Vec<String>>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                ReceivedEventData::JsonText(j) => self.data.lock().unwrap().push(j.to_string()),
                _ => unreachable!(),
            }
        }
    }
    let event_handler = Arc::new(MyEventHandler { data: data.clone() });
    let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
    std::thread::spawn(move || {
        let skel =
            BpfSkeletonBuilder::from_object_meta_and_object_buffer(&skel_json, &bpf_obj, None)
                .build()
                .unwrap()
                .load_and_attach()
                .unwrap();
        tx.send(skel.create_poll_handle()).unwrap();
        skel.wait_and_poll_to_handler(ExportFormatType::Json, Some(event_handler), None)
            .unwrap();
    });
    let handle = rx.recv().unwrap();
    std::process::Command::new("echo")
        .arg("abcd")
        .output()
        .unwrap();
    std::thread::sleep(Duration::from_secs(3));
    println!("{:?}", data.lock().unwrap());
    handle.terminate();
    let mut exec_found = false;
    let mut exit_found = false;
    for item in data.lock().unwrap().iter() {
        let json: Value = serde_json::from_str(item).unwrap();
        let json_obj = json.as_object().unwrap();
        if json_obj.contains_key("comm?") && json_obj.contains_key("fname") {
            exec_found = true;
        }
        if json_obj.contains_key("duration_ns") {
            exit_found = true;
        }
    }
    assert!(exec_found);
    assert!(exit_found);
}

// Member overflap
#[test]
#[should_panic(expected = "Field `ppid` overflapped with other fields")]
fn test_multiple_export_type_with_ring_buf_and_invalid_struct_1() {
    let assets_dir = get_assets_dir().join("multiple_export_ringbuf");
    let bpf_obj = std::fs::read(assets_dir.join("multiple.bpf.o")).unwrap();
    let skel_json = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets_dir.join("multiple-invalid-struct-1.json")).unwrap(),
    )
    .unwrap();
    let skel = BpfSkeletonBuilder::from_object_meta_and_object_buffer(&skel_json, &bpf_obj, None)
        .build()
        .unwrap()
        .load_and_attach()
        .unwrap();
    skel.wait_and_poll_to_handler(ExportFormatType::Json, None, None)
        .unwrap();
}

// Invalid offset
#[test]
#[should_panic]
fn test_multiple_export_type_with_ring_buf_and_invalid_struct_2() {
    let assets_dir = get_assets_dir().join("multiple_export_ringbuf");
    let bpf_obj = std::fs::read(assets_dir.join("multiple.bpf.o")).unwrap();
    let skel_json = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets_dir.join("multiple-invalid-struct-2.json")).unwrap(),
    )
    .unwrap();
    let skel = BpfSkeletonBuilder::from_object_meta_and_object_buffer(&skel_json, &bpf_obj, None)
        .build()
        .unwrap()
        .load_and_attach()
        .unwrap();
    skel.wait_and_poll_to_handler(ExportFormatType::Json, None, None)
        .unwrap();
}

#[test]
fn test_multiple_export_type_with_sample_map_1() {
    let assets_dir = get_assets_dir().join("multiple_export_sample_map");
    let bpf_obj = std::fs::read(assets_dir.join("multiple.bpf.o")).unwrap();
    let skel_json = serde_json::from_str::<EunomiaObjectMeta>(
        &std::fs::read_to_string(assets_dir.join("multiple.skel.json")).unwrap(),
    )
    .unwrap();

    let data_exec = Arc::new(Mutex::new(Vec::<Value>::default()));
    let data_exit = Arc::new(Mutex::new(Vec::<Value>::default()));
    struct MyEventHandler {
        data: Arc<Mutex<Vec<Value>>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                ReceivedEventData::JsonText(j) => self
                    .data
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(j).unwrap()),
                _ => unreachable!(),
            }
        }
    }
    let event_handler_exec = Arc::new(MyEventHandler {
        data: data_exec.clone(),
    });
    let event_handler_exit = Arc::new(MyEventHandler {
        data: data_exit.clone(),
    });

    let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
    std::thread::spawn(move || {
        let skel =
            BpfSkeletonBuilder::from_object_meta_and_object_buffer(&skel_json, &bpf_obj, None)
                .build()
                .unwrap()
                .load_and_attach()
                .unwrap();
        tx.send(skel.create_poll_handle()).unwrap();
        skel.wait_and_poll_to_handler_with_multiple_exporter(|name| match name {
            "map_exec" => Some((ExportFormatType::Json, event_handler_exec.clone(), None)),
            "map_exit" => Some((ExportFormatType::Json, event_handler_exit.clone(), None)),
            _ => unreachable!(),
        })
        .unwrap();
    });
    let handle = rx.recv().unwrap();
    std::process::Command::new("echo")
        .arg("abcd")
        .output()
        .unwrap();
    std::thread::sleep(Duration::from_secs(3));
    handle.terminate();
    println!("{:#?}", data_exec.lock().unwrap());
    println!("{:#?}", data_exit.lock().unwrap());
    assert!(data_exec
        .lock()
        .unwrap()
        .iter()
        .find(|v| v["value"]["comm"] == "echo")
        .is_some());
    assert!(data_exit
        .lock()
        .unwrap()
        .iter()
        .find(|v| v["value"]["comm"] == "echo")
        .is_some());
}
