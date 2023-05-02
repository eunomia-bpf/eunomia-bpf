//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{
    cell::RefCell,
    io::{BufRead, BufReader},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

use crate::{
    export_event::{EventHandler, ExportFormatType, ReceivedEventData},
    meta::ComposedObject,
    skeleton::handle::PollingHandle,
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

#[test]
fn test_pause_resume_terminate_1() {
    let skel = serde_json::from_str::<ComposedObject>(
        &std::fs::read_to_string(get_assets_dir().join("bootstrap.json")).unwrap(),
    )
    .unwrap();
    struct MyEventReceiver {
        data: Arc<Mutex<Vec<String>>>,
    }
    impl EventHandler for MyEventReceiver {
        fn handle_event(&self, _context: Option<Arc<dyn std::any::Any>>, data: ReceivedEventData) {
            match data {
                ReceivedEventData::JsonText(s) => self.data.lock().unwrap().push(s.to_owned()),
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let data = Arc::new(Mutex::new(Vec::new()));
    let event_handler = Arc::new(MyEventReceiver { data: data.clone() });
    let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();
    let join_handle: JoinHandle<Result<()>> = std::thread::spawn(move || {
        let skel = BpfSkeletonBuilder::from_json_package(&skel, None)
            .build()
            .unwrap();
        let skel = skel.load_and_attach().unwrap();
        tx.send(skel.create_poll_handle()).unwrap();
        skel.wait_and_poll_to_handler(ExportFormatType::Json, Some(event_handler), None)
            .unwrap();
        Ok(())
    });
    let polling_handle = rx.recv().unwrap();
    // Sleep 1s and try to get something
    std::thread::sleep(Duration::from_secs(1));
    polling_handle.set_pause(true);
    std::thread::sleep(Duration::from_secs(1));
    let count1 = data.lock().unwrap().len();
    // Sleep 3s, and check if nothing was added into result
    std::thread::sleep(Duration::from_secs(3));
    let count2 = data.lock().unwrap().len();
    assert_eq!(count1, count2);
    // Let it resume
    polling_handle.set_pause(false);
    std::thread::sleep(Duration::from_secs(1));
    // Sleep 3s, more things should be added result
    std::process::Command::new("sh").output().unwrap();
    std::thread::sleep(Duration::from_secs(3));
    let count3 = data.lock().unwrap().len();
    assert!(count3 > count2);
    // Terminate the worker
    polling_handle.terminate();
    join_handle.join().unwrap().unwrap();
}

#[test]
fn test_run_prog_with_static_const_vars() {
    let package: ComposedObject = serde_json::from_str(
        &std::fs::read_to_string(get_assets_dir().join("simple_prog_4").join("package.json"))
            .unwrap(),
    )
    .unwrap();
    let (handle_tx, handle_rx) = std::sync::mpsc::channel::<PollingHandle>();
    std::thread::spawn(move || {
        let skel = BpfSkeletonBuilder::from_json_package(&package, None)
            .build()
            .unwrap()
            .load_and_attach()
            .unwrap();
        handle_tx.send(skel.create_poll_handle()).unwrap();
        skel.wait_for_no_export_program().unwrap();
    });
    let handle = handle_rx.recv().unwrap();
    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .open("/sys/kernel/tracing/trace_pipe")
        .unwrap();
    let mut reader = BufReader::new(pipe);

    std::process::Command::new("echo")
        .arg("qaq")
        .output()
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    // Read twice to handle the interrupted line
    reader.read_line(&mut line).unwrap();

    assert!(line.contains("Created 305419896"));
    handle.terminate();
}
