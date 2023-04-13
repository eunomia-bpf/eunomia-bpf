//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{cell::RefCell, rc::Rc, sync::Arc};

use libbpf_rs::ObjectBuilder;
use serde::Deserialize;

use crate::{
    btf_container::BtfContainer,
    export_event::{
        tests::RRC, EventExporter, EventExporterBuilder, EventHandler, ExportFormatType,
        ExporterInternalImplementation,
    },
    meta::{ComposedObject, MapMeta, SampleMapType},
    tests::get_assets_dir,
};
struct LoadedThings {
    key_id: u32,
    value_id: u32,
    btf: Arc<BtfContainer>,
    package: ComposedObject,
}

fn load_things() -> LoadedThings {
    let assets = get_assets_dir();
    let package = serde_json::from_str::<ComposedObject>(
        &std::fs::read_to_string(assets.join("runqlat.json")).unwrap(),
    )
    .unwrap();
    let btf = Arc::new(BtfContainer::new_from_binary(&package.bpf_object[..]).unwrap());
    let bpf_obj = ObjectBuilder::default()
        .open_memory("runqlat", &package.bpf_object[..])
        .unwrap()
        .load()
        .unwrap();
    let hists_map = bpf_obj.map("hists").unwrap();
    let map_info = hists_map.info().unwrap();

    let key_type_id = map_info.info.btf_key_type_id;
    let value_type_id = map_info.info.btf_value_type_id;

    LoadedThings {
        key_id: key_type_id,
        value_id: value_type_id,
        btf,
        package,
    }
}

fn create_key_value_buffer() -> ([u8; 4], [u8; 120]) {
    let key_buffer = {
        let key_value: u32 = 0x12345678;
        key_value.to_le_bytes()
    };
    let value_buffer = {
        let mut value_buffer = [0u8; 120];
        let comm_str = b"COMM-STR\0";
        value_buffer[4 * 26..4 * 26 + comm_str.len()].copy_from_slice(comm_str);
        (0..26u32).into_iter().for_each(|v| {
            let bytes: [u8; 4] = (v + 1000).to_le_bytes();
            value_buffer[(v * 4) as usize..((v + 1) * 4) as usize].copy_from_slice(&bytes[..]);
        });
        value_buffer
    };
    (key_buffer, value_buffer)
}

#[derive(Deserialize, Debug)]
struct HistsMapValue {
    slots: [u32; 26],
    comm: String,
}
#[derive(Deserialize, Debug)]
struct HistsMapKey {
    #[serde(rename = "u32")]
    key_val: u32,
}
#[derive(Deserialize, Debug)]
struct HistsMap {
    key: HistsMapKey,
    value: HistsMapValue,
}

impl HistsMap {
    fn verify_with_default_value(&self) {
        assert_eq!(self.key.key_val, 0x12345678);
        assert_eq!(self.value.comm, "COMM-STR");
        for (i, v) in self.value.slots.iter().enumerate() {
            assert_eq!(*v as usize, i + 1000);
        }
    }
}

/*
Sampling map of runqlat:
Key: <TYPEDEF> 'u32' --> [7]
Value: <STRUCT> 'hist' sz:120 n:2
        #00 'slots' off:0 --> [23] // [u32; 26]
        #01 'comm' off:832 --> [25] // [u8; 16]

ty<7> <TYPEDEF> '__u32' --> [8]

ty<23> <ARRAY> n:26 idx-->[4] val-->[7]
ty<24> <INT> 'char' bits:8 off:0 enc:signed
ty<25> <ARRAY> n:16 idx-->[4] val-->[24]

 */

fn find_sample_map_mut(maps: &mut [MapMeta]) -> &mut MapMeta {
    let mut sample_map = None;
    for map in maps.iter_mut() {
        if map.sample.is_some() {
            sample_map = Some(map);
        }
    }
    let sample_map = sample_map.unwrap();
    sample_map
}

fn find_sample_map(maps: &[MapMeta]) -> &MapMeta {
    let mut sample_map = None;
    for map in maps.iter() {
        if map.sample.is_some() {
            sample_map = Some(map);
        }
    }
    let sample_map = sample_map.unwrap();
    sample_map
}

fn send_data(exporter: Arc<EventExporter>, key_buffer: &[u8], value_buffer: &[u8]) {
    match &exporter.internal_impl {
        ExporterInternalImplementation::KeyValueMapProcessor {
            event_processor, ..
        } => {
            event_processor
                .handle_event(key_buffer, value_buffer)
                .unwrap();
        }
        _ => panic!("Unexpected internal implementation"),
    };
}

fn create_exporter(
    things: &LoadedThings,
    handler: Arc<dyn EventHandler>,
    export_format: ExportFormatType,
) -> Arc<EventExporter> {
    let meta = &things.package.meta;
    let sample_map = find_sample_map(&meta.bpf_skel.maps[..]);

    let exporter = EventExporterBuilder::new()
        .set_export_event_handler(handler)
        .set_export_format(export_format)
        .build_for_map_sampling(
            things.key_id,
            things.value_id,
            &sample_map.sample.as_ref().unwrap(),
            &meta.export_types[..],
            things.btf.clone(),
        )
        .unwrap();
    exporter
}

#[test]
fn test_export_format_json() {
    let things = load_things();
    let received_data = Rc::new(RefCell::new(String::default()));
    struct MyEventHandler {
        data: RRC<String>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                crate::export_event::ReceivedEventData::JsonText(s) => {
                    self.data.replace(s.to_string());
                }
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let exporter = create_exporter(
        &things,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
        ExportFormatType::Json,
    );
    let (key_buffer, value_buffer) = create_key_value_buffer();
    send_data(exporter, &key_buffer[..], &value_buffer[..]);
    println!("{:?}", value_buffer);
    let inner_data = received_data.borrow();
    let decoded = serde_json::from_str::<HistsMap>(&inner_data).unwrap();
    println!("{:?}", decoded);
    decoded.verify_with_default_value();
}

const EXPECTED_OUTPUT_LOG2HISTS_LINES: [&str; 29] = [
    "key =  305419896",
    "comm = \"COMM-STR\"",
    "     (unit)              : count    distribution",
    "         0 -> 1          : 1000     |*************************************** |",
    "         2 -> 3          : 1001     |*************************************** |",
    "         4 -> 7          : 1002     |*************************************** |",
    "         8 -> 15         : 1003     |*************************************** |",
    "        16 -> 31         : 1004     |*************************************** |",
    "        32 -> 63         : 1005     |*************************************** |",
    "        64 -> 127        : 1006     |*************************************** |",
    "       128 -> 255        : 1007     |*************************************** |",
    "       256 -> 511        : 1008     |*************************************** |",
    "       512 -> 1023       : 1009     |*************************************** |",
    "      1024 -> 2047       : 1010     |*************************************** |",
    "      2048 -> 4095       : 1011     |*************************************** |",
    "      4096 -> 8191       : 1012     |*************************************** |",
    "      8192 -> 16383      : 1013     |*************************************** |",
    "     16384 -> 32767      : 1014     |*************************************** |",
    "     32768 -> 65535      : 1015     |*************************************** |",
    "     65536 -> 131071     : 1016     |*************************************** |",
    "    131072 -> 262143     : 1017     |*************************************** |",
    "    262144 -> 524287     : 1018     |*************************************** |",
    "    524288 -> 1048575    : 1019     |*************************************** |",
    "   1048576 -> 2097151    : 1020     |*************************************** |",
    "   2097152 -> 4194303    : 1021     |*************************************** |",
    "   4194304 -> 8388607    : 1022     |*************************************** |",
    "   8388608 -> 16777215   : 1023     |*************************************** |",
    "  16777216 -> 33554431   : 1024     |*************************************** |",
    "  33554432 -> 67108863   : 1025     |****************************************|",
];

#[test]
fn test_export_format_plain_text_log2_hists() {
    let mut things = load_things();
    find_sample_map_mut(&mut things.package.meta.bpf_skel.maps)
        .sample
        .as_mut()
        .unwrap()
        .ty = SampleMapType::Log2Hist;
    let received_data = Rc::new(RefCell::new(Vec::new()));
    struct MyEventHandler {
        data: RRC<Vec<String>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                crate::export_event::ReceivedEventData::PlainText(s) => {
                    self.data.borrow_mut().push(s.to_string());
                }
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let exporter = create_exporter(
        &things,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
        ExportFormatType::PlainText,
    );
    let (key_buffer, value_buffer) = create_key_value_buffer();
    send_data(exporter, &key_buffer[..], &value_buffer[..]);
    let inner_data = received_data.borrow();
    let merged_test = inner_data.concat();
    let lines = merged_test.lines().collect::<Vec<&str>>();

    assert_eq!(&lines[..], &EXPECTED_OUTPUT_LOG2HISTS_LINES[..]);
}

const DEFAULT_KV_OUTPUT_SEC1: &str = "TIME     U32    SLOTS  COMM   ";
const DEFAULT_KV_OUTPUT_SEC2: &str = "{\"u32\":305419896} {\"comm\":\"COMM-STR\",\"slots\":[1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011,1012,1013,1014,1015,1016,1017,1018,1019,1020,1021,1022,1023,1024,1025]}";

#[test]
fn test_export_format_plain_text_default_kv() {
    let mut things = load_things();
    find_sample_map_mut(&mut things.package.meta.bpf_skel.maps)
        .sample
        .as_mut()
        .unwrap()
        .ty = SampleMapType::DefaultKV;
    let received_data = Rc::new(RefCell::new(Vec::new()));
    struct MyEventHandler {
        data: RRC<Vec<String>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                crate::export_event::ReceivedEventData::PlainText(s) => {
                    self.data.borrow_mut().push(s.to_string());
                }
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let exporter = create_exporter(
        &things,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
        ExportFormatType::PlainText,
    );
    let (key_buffer, value_buffer) = create_key_value_buffer();
    send_data(exporter, &key_buffer[..], &value_buffer[..]);
    let inner_data = received_data.borrow();
    println!("{:?}", inner_data);
    assert_eq!(inner_data[0], DEFAULT_KV_OUTPUT_SEC1);
    let sec2_without_time = inner_data[1].split_once(" ").unwrap().1;
    assert_eq!(sec2_without_time, DEFAULT_KV_OUTPUT_SEC2);
}

#[test]
fn test_export_format_raw() {
    let things = load_things();
    let received_data = Rc::new(RefCell::new((vec![], vec![])));
    struct MyEventHandler {
        data: RRC<(Vec<u8>, Vec<u8>)>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                crate::export_event::ReceivedEventData::KeyValueBuffer { key, value } => {
                    self.data.replace((key.to_vec(), value.to_vec()));
                }
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let exporter = create_exporter(
        &things,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
        ExportFormatType::RawEvent,
    );
    let (key_buffer, value_buffer) = create_key_value_buffer();
    send_data(exporter, &key_buffer[..], &value_buffer[..]);
    let data = received_data.borrow();
    assert_eq!(data.0, key_buffer);
    assert_eq!(data.1, value_buffer);
}
