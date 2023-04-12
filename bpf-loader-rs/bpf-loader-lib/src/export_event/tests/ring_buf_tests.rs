use std::{cell::RefCell, rc::Rc, sync::Arc};

use crate::{
    btf_container::BtfContainer,
    export_event::{
        tests::{load_triple, RRC},
        EventExporter, EventExporterBuilder, EventHandler, ExportFormatType,
        ExporterInternalImplementation,
    },
    meta::EunomiaObjectMeta,
    tests::ExampleTestStruct,
};

fn send_data(exporter: Arc<EventExporter>, data: &[u8]) {
    match &exporter.internal_impl {
        ExporterInternalImplementation::RingBufProcessor {
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
        .build_for_ringbuf(&skel.export_types[..], btf)
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

const EXPECTED_PLAIN_TEXT_OUTPUT_LINE2:&str = "[[[0,1,2,3],[256,257,258,259],[512,513,514,515]],[[65536,65537,65538,65539],[65792,65793,65794,65795],[66048,66049,66050,66051]]] \"A-String\" [\"hello 0\",\"hello 1\",\"hello 2\",\"hello 3\",\"hello 4\",\"hello 5\",\"hello 6\",\"hello 7\",\"hello 8\",\"hello 9\"] 1.2300000190734863 4.56 18 -18 4660 -4660 305419896 -305419896 1311768467463790320 -1311768467463790320 \"E_A(0)\"";
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
