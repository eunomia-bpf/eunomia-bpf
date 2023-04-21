//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::io::{stdin, Write};
use std::{env, fs};

use oci_distribution::{secrets::RegistryAuth, Reference, RegistryOperation};
use rpassword::prompt_password;
use serde_yaml::{self, Value};
use url::Url;

use crate::{
    error::{EcliError, EcliResult},
    oci::get_client,
};

use super::{get_auth_save_file, AuthInfo, LoginInfo};

fn read_login_user() -> String {
    print!("username:");
    std::io::stdout().flush().unwrap();
    stdin().lines().next().unwrap().unwrap()
}

fn read_login_password() -> String {
    prompt_password("password:").unwrap()
}

fn read_login_token() -> String {
    print!("token:");
    std::io::stdout().flush().unwrap();
    stdin().lines().next().unwrap().unwrap()
}

fn get_gh_env_token() -> (String, String) {
    let gh_config_path = home::home_dir().unwrap().join(".config/gh/hosts.yml");
    if gh_config_path.exists() {
        let gh_config = fs::File::open(gh_config_path).unwrap();
        let config: Value = serde_yaml::from_reader(gh_config).unwrap();
        return (
            config["github.com"]["user"].as_str().unwrap().to_string(),
            config["github.com"]["oauth_token"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    let username = read_login_user();

    static GITHUB_TOKEN: &str = "GITHUB_TOKEN";
    if let Ok(token) = env::var(GITHUB_TOKEN) {
        return (username, token);
    }

    return (username, read_login_token());
}

async fn login_registry(url: Url, username: &str, token: &str) -> EcliResult<()> {
    let Some(host) = url.host_str() else {
        return Err(EcliError::ParamErr("url format incorrect".to_string()))
    };
    let mut auth_info = AuthInfo::get()?;
    let login_info = LoginInfo::new(host, username, token);

    v2_login(&url, &login_info).await?;
    auth_info.set_login_info(login_info);
    auth_info.write_to_file(&mut get_auth_save_file()?)?;
    println!("Login success");
    Ok(())
}

/// Login into an OCI registry
/// Will prompt and read username and password from stdin
pub async fn login(u: String) -> EcliResult<()> {
    let url = Url::parse(u.as_str()).map_err(|e| EcliError::ParamErr(e.to_string()))?;

    if url.as_str() == "https://ghcr.io/" {
        let (user, token) = get_gh_env_token().into();
        login_registry(url, &user, &token).await?;
    } else {
        login_registry(url, &read_login_user(), &read_login_password()).await?;
    }
    Ok(())
}
/// Login into an OCI registry
/// Will use username and password in LoginInfo
async fn v2_login(url: &Url, login_info: &LoginInfo) -> EcliResult<()> {
    let (username, password) = login_info.get_user_pwd()?;
    let mut client = get_client(url)?;
    let reference = Reference::with_tag(url.host_str().unwrap().into(), "/".into(), "".into());
    client
        .auth(
            &reference,
            &RegistryAuth::Basic(username, password),
            RegistryOperation::Push,
        )
        .await
        .map_err(|e| EcliError::LoginError(e.to_string()))
}
