use std::path;

use anyhow::Result;

static EUNOMIA_HOME_ENV: &str = "EUNOMIA_HOME";
static FHS_EUNOMIA_HOME_ENTRY: &str = "/usr/share/eunomia";

/// Get home directory from env
pub fn get_eunomia_home() -> Result<String> {
    let eunomia_home = std::env::var(EUNOMIA_HOME_ENV);
    match eunomia_home {
        Ok(home) => Ok(home),
        Err(_) => match home::home_dir() {
            Some(home) => {
                let home = home.join(".eunomia");
                Ok(home.to_str().unwrap().to_string())
            }
            None => {
                if path::Path::new(FHS_EUNOMIA_HOME_ENTRY).exists() {
                    Ok(FHS_EUNOMIA_HOME_ENTRY.to_string())
                } else {
                    Err(anyhow::anyhow!("HOME is not found"))
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::{get_eunomia_home, EUNOMIA_HOME_ENV, FHS_EUNOMIA_HOME_ENTRY};

    #[test]
    fn test_get_eunomia_home() {
        let eunomia_home_from_env = std::env::var(EUNOMIA_HOME_ENV);
        let eunomia_home_from_home = home::home_dir().unwrap();

        match eunomia_home_from_env {
            Ok(path) => assert_eq!(get_eunomia_home().unwrap(), path),
            Err(_) => {
                if get_eunomia_home().is_err() {
                    assert!(true)
                }

                if eunomia_home_from_home.exists() {
                    assert_eq!(
                        get_eunomia_home().unwrap(),
                        eunomia_home_from_home
                            .join(".eunomia")
                            .into_os_string()
                            .into_string()
                            .unwrap()
                    );
                } else {
                    assert_eq!(
                        get_eunomia_home().unwrap(),
                        FHS_EUNOMIA_HOME_ENTRY.to_string()
                    )
                }
            }
        }
    }
}
