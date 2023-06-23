use oci_distribution::annotations;

use crate::{parse_annotations, parse_annotations_and_insert_image_title};

#[test]
fn simple_annotations_test_1() {
    let s = ["aaa=bbb", "ccc=ddd", "eee=fff", "a=b=c"];
    let ret = parse_annotations(&s).unwrap();
    assert_eq!(ret.get("aaa"), Some(&"bbb".to_owned()));
    assert_eq!(ret.get("ccc"), Some(&"ddd".to_owned()));
    assert_eq!(ret.get("eee"), Some(&"fff".to_owned()));
    assert_eq!(ret.get("a"), Some(&"b=c".to_owned()));
}

#[test]
#[should_panic(expected = "Annotations should be like")]
fn simple_annotations_test_2() {
    let s = ["aaa"];
    parse_annotations(&s).unwrap();
}

#[test]
fn test_with_title_insertion_1() {
    let s = ["aaa=bbb", "ccc=ddd", "eee=fff", "a=b=c"];
    let ret = parse_annotations_and_insert_image_title(&s, "module-name".into()).unwrap();
    assert_eq!(
        ret.get(&annotations::ORG_OPENCONTAINERS_IMAGE_TITLE.to_owned()),
        Some(&"module-name".to_owned())
    );
}

#[test]
fn test_with_title_insertion_2() {
    let s = [
        "aaa=bbb",
        "ccc=ddd",
        "eee=fff",
        "a=b=c",
        "org.opencontainers.image.title=module-name-1",
    ];
    let ret = parse_annotations_and_insert_image_title(&s, "module-name".into()).unwrap();
    assert_eq!(
        ret.get(&annotations::ORG_OPENCONTAINERS_IMAGE_TITLE.to_owned()),
        Some(&"module-name-1".to_owned())
    );
}
