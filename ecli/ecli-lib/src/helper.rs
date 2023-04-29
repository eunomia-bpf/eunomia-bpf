use crate::error::{Error, Result};

const EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";

/// Get eunomia home directory
pub fn get_eunomia_home() -> Result<String> {
    let eunomia_home = std::env::var(EUNOMIA_HOME_ENV);
    if let Ok(home) = eunomia_home {
        Ok(home)
    } else if let Some(home) = home::home_dir() {
        let home = home.join(".eunomia");
        if !home.exists() {
            std::fs::create_dir_all(&home).map_err(Error::IOErr)?;
        }
        Ok(home.to_string_lossy().to_string())
    } else {
        Err(Error::Other(
            "home dir not found. Please set EUNOMIA_HOME env.".to_string(),
        ))
    }
}
