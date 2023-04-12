use serde_json::{json, Value};

use crate::{
    meta::{
        DataSectionMeta, DataSectionVariableMeta, ExportedTypesStructMemberMeta,
        ExportedTypesStructMeta, MapMeta, ProgMeta,
    },
    tests::get_assets_dir,
};

use super::ComposedObject;

#[test]
fn test_deserialize_meta() {
    let json_str = std::fs::read_to_string(get_assets_dir().join("bootstrap.json")).unwrap();
    let json_val: Value = serde_json::from_str(&json_str).unwrap();
    let decoded: ComposedObject = serde_json::from_value(json_val).unwrap();
    assert_eq!(decoded.bpf_object.len(), 47496);
    let bpf_skel = &decoded.meta.bpf_skel;
    let data_section = &bpf_skel.data_sections;
    assert_eq!(data_section.len(), 2);
    assert!(data_section.contains(&DataSectionMeta {
        name: ".rodata".into(),
        variables: vec![DataSectionVariableMeta {
            name: "min_duration_ns".into(),
            ty: "unsigned long long".into(),
            value: None,
            others: json!({}),
            cmdarg: Default::default(),
            description: None
        }]
    }));
    assert!(data_section.contains(&DataSectionMeta {
        name: ".bss".into(),
        variables: vec![DataSectionVariableMeta {
            name: "__eunomia_dummy_event_ptr".into(),
            ty: "struct event *".into(),
            value: None,
            others: json!({}),
            cmdarg: Default::default(),
            description: None
        }]
    }));
    let maps = &bpf_skel.maps;
    assert_eq!(maps.len(), 4);
    assert!(maps.contains(&MapMeta {
        ident: "exec_start".into(),
        name: "exec_start".into(),
        mmaped: false,
        sample: None
    }));
    assert!(maps.contains(&MapMeta {
        ident: "rb".into(),
        name: "rb".into(),
        mmaped: false,
        sample: None
    }));
    assert!(maps.contains(&MapMeta {
        ident: "rodata".into(),
        name: "client_b.rodata".into(),
        mmaped: true,
        sample: None
    }));
    assert!(maps.contains(&MapMeta {
        ident: "bss".into(),
        name: "client_b.bss".into(),
        mmaped: true,
        sample: None
    }));
    assert_eq!(bpf_skel.obj_name, "client_bpf");
    let progs = &bpf_skel.progs;
    assert_eq!(progs.len(), 2);
    assert!(progs.contains(&ProgMeta {
        name: "handle_exec".into(),
        link: true,
        attach: "tp/sched/sched_process_exec".into(),
        others: json!({})
    }));
    assert!(progs.contains(&ProgMeta {
        name: "handle_exit".into(),
        link: true,
        attach: "tp/sched/sched_process_exit".into(),
        others: json!({})
    }));
    let export_types = &decoded.meta.export_types;
    assert_eq!(export_types.len(), 1);
    assert!(export_types.contains(&ExportedTypesStructMeta {
        name: "event".into(),
        members: vec![
            ExportedTypesStructMemberMeta {
                name: "pid".into(),
                ty: "int".into()
            },
            ExportedTypesStructMemberMeta {
                name: "ppid".into(),
                ty: "int".into()
            },
            ExportedTypesStructMemberMeta {
                name: "exit_code".into(),
                ty: "unsigned int".into()
            },
            ExportedTypesStructMemberMeta {
                name: "duration_ns".into(),
                ty: "unsigned long long".into()
            },
            ExportedTypesStructMemberMeta {
                name: "comm".into(),
                ty: "char[16]".into()
            },
            ExportedTypesStructMemberMeta {
                name: "filename".into(),
                ty: "char[127]".into()
            },
            ExportedTypesStructMemberMeta {
                name: "exit_event".into(),
                ty: "bool".into()
            },
            ExportedTypesStructMemberMeta {
                name: "et".into(),
                ty: "enum event_type".into()
            },
        ],
        size: 176,
        type_id: 613
    }));
}
