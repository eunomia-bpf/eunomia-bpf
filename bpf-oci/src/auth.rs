use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use oci_distribution::secrets::RegistryAuth;
use serde::Deserialize;

#[derive(Deserialize)]
struct AuthEntry {
    auth: String,
}

impl AuthEntry {
    pub fn extract_registry_auth(&self) -> Result<RegistryAuth> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.auth)
            .with_context(|| anyhow!("Failed to decode base64"))?;
        let decoded_str =
            String::from_utf8(decoded).with_context(|| anyhow!("Invalid utf8 chars"))?;
        let (user, pass) = decoded_str
            .split_once(':')
            .with_context(|| anyhow!("Unable to find `:` in the auth string"))?;
        Ok(RegistryAuth::Basic(user.to_owned(), pass.to_owned()))
    }
}

#[derive(Deserialize)]
struct DockerConfig {
    auths: HashMap<String, AuthEntry>,
}

pub trait RegistryAuthExt {
    fn load_from_docker(path: Option<&Path>, registry: &str) -> Result<Self>
    where
        Self: Sized;

    fn load_from_prompt() -> Result<Self>
    where
        Self: Sized;
}

impl RegistryAuthExt for RegistryAuth {
    fn load_from_docker(path: Option<&Path>, registry: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let docker_cfg_path = match path.map(|v| v.to_path_buf()) {
            Some(v) => v,
            None => home::home_dir()
                .with_context(|| anyhow!("Unable to retrive home directory"))?
                .join(".docker/config.json"),
        };
        let config: DockerConfig = serde_json::from_str(
            &std::fs::read_to_string(&docker_cfg_path)
                .with_context(|| anyhow!("Failed to read docker config"))?,
        )
        .with_context(|| anyhow!("Failed to deserialize docker config"))?;
        let auth_entry = config.auths.get(registry).with_context(|| {
            anyhow!(
                "Unable to find auth entry named `{}` in {:?}",
                registry,
                docker_cfg_path
            )
        })?;
        auth_entry.extract_registry_auth()
    }
    fn load_from_prompt() -> Result<Self>
    where
        Self: Sized,
    {
        print!("Username: ");
        let mut username = String::default();
        std::io::stdin().read_line(&mut username)?;
        let password = rpassword::prompt_password("Password: ")?;
        Ok(Self::Basic(username, password))
    }
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use oci_distribution::secrets::RegistryAuth;
    use tempfile::{tempdir, TempDir};

    use super::RegistryAuthExt;

    fn write_temp_file() -> (PathBuf, TempDir) {
        let dir = tempdir().unwrap();
        let data = include_bytes!("../assets/docker-config-test.json");
        std::fs::write(dir.path().join("test.json"), data).unwrap();
        (dir.path().join("test.json"), dir)
    }

    #[test]
    fn test_load_docker_config() {
        let (f, _dir) = write_temp_file();
        let auth = RegistryAuth::load_from_docker(Some(&f), "ghcr.io").unwrap();
        match auth {
            RegistryAuth::Basic(a, b) => {
                assert_eq!(a, "aaa");
                assert_eq!(b, "bbb");
            }
            _ => unreachable!(),
        }
    }
}
