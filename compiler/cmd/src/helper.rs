use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

pub(crate) fn get_eunomia_data_dir() -> Result<PathBuf> {
    let dir = home::home_dir()
        .ok_or_else(|| anyhow!("Unable to get home directory of the current user"))?
        .join(".eunomia");
    if !dir.exists() {
        std::fs::create_dir(&dir).with_context(|| {
            anyhow!(
                "Unable to create data directory for eunomia: {}",
                dir.to_string_lossy()
            )
        })?;
    }
    Ok(dir)
}
