use std::path::PathBuf;

pub(crate) fn get_test_assets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test")
}
