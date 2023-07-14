//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{
    btf_container::BtfContainer,
    export_event::{
        tests::{load_triple, RRC},
        EventExporter, EventExporterBuilder, EventHandler, ExportFormatType,
        ExporterInternalImplementation,
    },
    meta::{BufferValueInterpreter, EunomiaObjectMeta},
    tests::ExampleTestStruct,
};

use super::load_triple_custom;

fn send_data(exporter: Arc<EventExporter>, data: &[u8]) {
    match &exporter.internal_impl {
        ExporterInternalImplementation::BufferValueProcessor {
            event_processor, ..
        } => {
            event_processor.handle_event(&data).unwrap();
        }
        _ => panic!("Unexpected internal implementation"),
    };
}

fn create_exporter(
    btf: Arc<BtfContainer>,
    skel: &EunomiaObjectMeta,
    export_format: ExportFormatType,
    handler: Arc<dyn EventHandler>,
) -> Arc<EventExporter> {
    let exporter = EventExporterBuilder::new()
        .set_export_event_handler(handler)
        .set_export_format(export_format)
        .build_for_single_value(
            &skel.export_types[0],
            btf,
            &BufferValueInterpreter::DefaultStruct,
        )
        .unwrap();
    exporter
}

#[test]
fn test_export_format_json() {
    let (btf, bin_data, skel) = load_triple();
    let received_data = Rc::new(RefCell::new(String::default()));

    struct MyEventHandler {
        data: RRC<String>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<std::sync::Arc<dyn std::any::Any>>,
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
        btf,
        &skel,
        ExportFormatType::Json,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
    );

    send_data(exporter.clone(), &bin_data[..]);
    let inner_data = received_data.borrow();
    let data: ExampleTestStruct = serde_json::from_str(inner_data.as_str()).unwrap();
    data.test_with_example_data();
}

const EXPECTED_PLAIN_TEXT_OUTPUT_LINE2:&str = "[[[0,1,2,3],[256,257,258,259],[512,513,514,515]],[[65536,65537,65538,65539],[65792,65793,65794,65795],[66048,66049,66050,66051]]] A-String [\"hello 0\",\"hello 1\",\"hello 2\",\"hello 3\",\"hello 4\",\"hello 5\",\"hello 6\",\"hello 7\",\"hello 8\",\"hello 9\"] 1.2300000190734863 4.56 18 -18 4660 -4660 305419896 -305419896 1311768467463790320 -1311768467463790320 E_A(0)";
const EXPECTED_PLAIN_TEXT_OUTPUT_LINE1:&str = "TIME     ARR1   STR    STR_ARR FT     DBL    U8V    I8V    U16V   I16V   U32V   I32V   U64V   I64V   E      ";

#[test]
fn test_export_format_plain_text() {
    let (btf, bin_data, skel) = load_triple();
    let received_data = Rc::new(RefCell::new(Vec::new()));

    struct MyEventHandler {
        data: RRC<Vec<String>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<std::sync::Arc<dyn std::any::Any>>,
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
        btf,
        &skel,
        ExportFormatType::PlainText,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
    );

    send_data(exporter.clone(), &bin_data[..]);
    let inner_data = received_data.borrow();
    println!("{:?}", inner_data);
    assert_eq!(inner_data[0], EXPECTED_PLAIN_TEXT_OUTPUT_LINE1);
    let output_without_time = inner_data[1].split_once("  ").unwrap().1;
    println!("{:?}", output_without_time);
    assert_eq!(output_without_time, EXPECTED_PLAIN_TEXT_OUTPUT_LINE2);
}

#[test]
fn test_export_format_raw() {
    let (btf, bin_data, skel) = load_triple();
    let received_data = Rc::new(RefCell::new(Vec::<u8>::new()));

    struct MyEventHandler {
        data: RRC<Vec<u8>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<std::sync::Arc<dyn std::any::Any>>,
            data: crate::export_event::ReceivedEventData,
        ) {
            match data {
                crate::export_event::ReceivedEventData::Buffer(s) => {
                    self.data.replace(s.to_vec());
                }
                _ => panic!("Unexpected data type"),
            }
        }
    }
    let exporter = create_exporter(
        btf,
        &skel,
        ExportFormatType::RawEvent,
        Arc::new(MyEventHandler {
            data: received_data.clone(),
        }),
    );

    send_data(exporter.clone(), &bin_data[..]);
    let inner_data = received_data.borrow();
    assert_eq!(&inner_data[..], &bin_data[..]);
}

const STACKTRACE_EXPECTED_OUTPUT:&str = "COMM: test-comm (pid=4660) @ CPU 22136\nKernel:\n0000000000010000\n0000000000010001\n0000000000010002\n0000000000010003\n0000000000010004\n0000000000010005\n0000000000010006\n0000000000010007\n0000000000010008\n0000000000010009\n000000000001000a\n000000000001000b\n000000000001000c\n000000000001000d\n000000000001000e\n000000000001000f\nUserspace:\n0000000000010000\n0000000000010001\n0000000000010002\n0000000000010003\n0000000000010004\n0000000000010005\n0000000000010006\n0000000000010007\n0000000000010008\n0000000000010009\n000000000001000a\n000000000001000b\n000000000001000c\n000000000001000d\n000000000001000e\n000000000001000f\n0000000000010010\n0000000000010011\n0000000000010012\n0000000000010013\n0000000000010014\n0000000000010015\n0000000000010016\n0000000000010017\n0000000000010018\n0000000000010019\n000000000001001a\n000000000001001b\n000000000001001c\n000000000001001d\n000000000001001e\n000000000001001f\n0000000000010020\n0000000000010021\n0000000000010022\n0000000000010023\n0000000000010024\n0000000000010025\n0000000000010026\n0000000000010027\n0000000000010028\n0000000000010029\n000000000001002a\n000000000001002b\n000000000001002c\n000000000001002d\n000000000001002e\n000000000001002f\n0000000000010030\n0000000000010031\n0000000000010032\n0000000000010033\n0000000000010034\n0000000000010035\n0000000000010036\n0000000000010037\n0000000000010038\n0000000000010039\n000000000001003a\n000000000001003b\n000000000001003c\n000000000001003d\n000000000001003e\n000000000001003f\n0000000000010040\n0000000000010041\n0000000000010042\n0000000000010043\n0000000000010044\n0000000000010045\n0000000000010046\n0000000000010047\n0000000000010048\n0000000000010049\n000000000001004a\n000000000001004b\n000000000001004c\n000000000001004d\n000000000001004e\n000000000001004f\n0000000000010050\n0000000000010051\n0000000000010052\n0000000000010053\n0000000000010054\n0000000000010055\n0000000000010056\n0000000000010057\n0000000000010058\n0000000000010059\n000000000001005a\n000000000001005b\n000000000001005c\n000000000001005d\n000000000001005e\n000000000001005f\n0000000000010060\n0000000000010061\n0000000000010062\n0000000000010063\n0000000000010064\n0000000000010065\n0000000000010066\n0000000000010067\n0000000000010068\n0000000000010069\n000000000001006a\n000000000001006b\n000000000001006c\n000000000001006d\n000000000001006e\n000000000001006f\n0000000000010070\n0000000000010071\n0000000000010072\n0000000000010073\n0000000000010074\n0000000000010075\n0000000000010076\n0000000000010077\n0000000000010078\n0000000000010079\n000000000001007a\n000000000001007b\n000000000001007c\n000000000001007d\n000000000001007e\n000000000001007f\n";

#[test]
fn test_stacktrace_exporter() {
    /*
        The dumper struct has layout like
        [18] STRUCT 'stacktrace_event' size=2080 vlen=7
        'pid' type_id=19 bits_offset=0 <UINT32>
        'cpu_id' type_id=19 bits_offset=32 <UINT32>
        'comm' type_id=21 bits_offset=64 <char[16]>
        'kstack_sz' type_id=22 bits_offset=192 <INT32>
        'ustack_sz' type_id=22 bits_offset=224 <INT32>
        'kstack' type_id=23 bits_offset=256 <UINT64[128]>
        'ustack' type_id=23 bits_offset=8448 <UINT64[128]>


        Test data were generated using the following C code:
        struct ST {
            uint32_t pid;
            uint32_t cpu_id;
            char comm[16];
            int32_t kstack_sz;
            int32_t ustack_sz;
            uint64_t kstack[128];
            uint64_t ustack[128];
        };
        int main() {
            struct ST data;
            assert(sizeof(data) == 2080);
            data.pid = 0x1234;
            data.cpu_id = 0x5678;
            strcpy(data.comm, "test-comm");
            data.kstack_sz = 16;
            data.ustack_sz = 128;
            for (int i = 0; i < data.kstack_sz; i++) {
                data.kstack[i] = (1 << 16) | i;
            }
            for (int i = 0; i < data.ustack_sz; i++) {
                data.ustack[i] = (1 << 16) | i;
            }
            FILE* fp = fopen("test.bin", "w");
            assert(fp);
            fwrite(&data, sizeof(data), 1, fp);
            fclose(fp);
            return 0;
        }

    */
    let (btf, dummy_bin, skel) = load_triple_custom(
        "profile_test/profile.bpf.o",
        "profile_test/test.bin",
        "profile_test/profile.skel.json",
    );
    let received_data = Rc::new(RefCell::new(Vec::new()));

    struct MyEventHandler {
        data: RRC<Vec<String>>,
    }
    impl EventHandler for MyEventHandler {
        fn handle_event(
            &self,
            _context: Option<std::sync::Arc<dyn std::any::Any>>,
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

    let exporter = EventExporterBuilder::new()
        .set_export_event_handler(Arc::new(MyEventHandler {
            data: received_data.clone(),
        }))
        .set_export_format(ExportFormatType::PlainText)
        .build_for_single_value(
            &skel.export_types[0],
            btf,
            &skel.bpf_skel.maps[0].intepreter,
        )
        .unwrap();

    send_data(exporter.clone(), &dummy_bin[..]);
    let inner_data = received_data.borrow()[0].clone();
    assert_eq!(inner_data, STACKTRACE_EXPECTED_OUTPUT);
}
