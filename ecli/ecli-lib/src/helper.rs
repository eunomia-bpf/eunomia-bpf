use crate::error::{Error, Result};
use std::env::var;
use std::path::PathBuf;

const EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";

/// Get eunomia home directory
pub fn get_eunomia_home() -> Result<String> {
    if let Ok(e) = var(EUNOMIA_HOME_ENV) {
        return Ok(e.into());
    };

    // search from xdg standard directory
    let eunomia_home_search_path: Vec<PathBuf> = if let Ok(e) = var("XDG_DATA_HOME") {
        e.split(':')
            .map(|s| PathBuf::from(format!("{s}/eunomia")))
            .collect()
    } else {
        if let Ok(e) = var("HOME") {
            let home_dir = PathBuf::from(e);
            let eunomia_home = home_dir.join(".local/share/eunomia");

            if home_dir.exists() {
                if !eunomia_home.exists() {
                    std::fs::create_dir_all(&eunomia_home).map_err(Error::IOErr)?
                }
                return Ok(eunomia_home.to_string_lossy().to_string());
            }
        }
        Vec::new()
    };

    return eunomia_home_search_path
        .into_iter()
        .find(|p| p.exists())
        .ok_or(Error::Other(
            "eunomia data home not found, try setting `EUNOMIA_HOME`".to_string(),
        ))
        .map(|p| p.to_string_lossy().to_string());
}
