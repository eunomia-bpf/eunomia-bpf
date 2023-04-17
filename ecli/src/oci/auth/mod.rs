//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
mod login;
mod logout;

pub use login::login;
pub use logout::logout;
use url::Url;

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use base64::{engine::general_purpose, Engine};
use eunomia_rs::get_eunomia_home;
use serde::{Deserialize, Serialize};

use crate::error::{EcliError, EcliResult};

const AUTH_FILE: &str = "eunomia_auth.json";

/// Info used to login into an OCI registry
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LoginInfo {
    url: String,
    // auth with the format: base64Encode("username:password")
    auth: String,
}

impl LoginInfo {
    /// Create a `LoginInfo`
    /// url - The url to the registry
    /// user - username
    /// pwd - password
    pub fn new(url: &str, user: &str, pwd: &str) -> Self {
        Self {
            url: String::from(url),
            auth: general_purpose::STANDARD.encode(format!("{}:{}", user, pwd)),
        }
    }

    fn get_user_pwd(&self) -> EcliResult<(String, String)> {
        let dec = general_purpose::STANDARD
            .decode(&self.auth)
            .map_err(|e| EcliError::SerializeError(e.to_string()))?;
        let Some(idx) = dec.iter().position(|x|*x==b':') else {
            return Err(EcliError::SerializeError("auth info format incorrect".to_string()))
        };

        let (user, pwd) = dec.split_at(idx);
        Ok((
            String::from_utf8_lossy(user).to_string(),
            String::from_utf8_lossy(&pwd[1..]).to_string(),
        ))
    }
}

/// The AuthInfo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthInfo(Vec<LoginInfo>);

impl AuthInfo {
    /// Get `AuthInfo` from the default cache file
    pub fn get() -> EcliResult<Self> {
        AuthInfo::read_from_file(&mut get_auth_save_file()?).map_err(|e| {
            if matches!(e, EcliError::SerializeError(_)) {
                EcliError::SerializeError(
                    "serialize auth config file fail, maybe the file corrupt".to_string(),
                )
            } else {
                e
            }
        })
    }
    fn read_from_file(file: &mut File) -> EcliResult<AuthInfo> {
        let mut data = vec![];
        file.read_to_end(&mut data).map_err(EcliError::IOErr)?;
        if data.is_empty() {
            return Ok(Self(vec![]));
        }
        serde_json::from_slice(&data).map_err(|e| EcliError::SerializeError(e.to_string()))
    }

    fn write_to_file(&self, file: &mut File) -> EcliResult<()> {
        // TODO backup the old file
        file.set_len(0).map_err(EcliError::IOErr)?;
        file.write_all(
            serde_json::to_vec(self)
                .map_err(|e| EcliError::SerializeError(e.to_string()))?
                .as_ref(),
        )
        .map_err(EcliError::IOErr)
    }

    /// return (username, password)
    fn get_auth_info_by_url(&self, url: &str) -> EcliResult<(String, String)> {
        for i in self.0.iter() {
            if i.url == url {
                return i.get_user_pwd();
            }
        }
        Err(EcliError::LoginInfoNotFoundError(
            "url have no login info".to_string(),
        ))
    }
    /// Set the login info
    pub fn set_login_info(&mut self, login_info: LoginInfo) {
        if let Some(idx) = self.0.iter().position(|x| x.url == login_info.url) {
            let _ = std::mem::replace(&mut self.0[idx], login_info);
        } else {
            self.0.push(login_info);
        }
    }
    /// Remove the login info
    pub fn remove_login_info(&mut self, url: &str) -> EcliResult<()> {
        let Some(idx) = self.0.iter().position(|x|x.url==url) else {
            return Err(EcliError::ParamErr(format!("auth info of url: {} not found",url)));
        };
        self.0.remove(idx);
        Ok(())
    }
}
/// Extract auth ingo from a URL
pub fn get_auth_info_by_url(url: &Url) -> EcliResult<(String, String)> {
    if !url.username().is_empty() {
        return Ok((
            url.username().into(),
            url.password().unwrap_or_default().into(),
        ));
    }
    let auth_info = AuthInfo::get()?;
    auth_info.get_auth_info_by_url(url.host_str().unwrap())
}

fn get_auth_save_file() -> EcliResult<File> {
    let home_dir = get_eunomia_home().map_err(|e| EcliError::Other(e.to_string()))?;
    let mut path = PathBuf::from(home_dir);
    if !path.exists() {
        fs::create_dir_all(&path).map_err(EcliError::IOErr)?;
    }
    path.push(AUTH_FILE);

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(EcliError::IOErr)
}

#[cfg(test)]
mod test {
    use url::Url;

    use super::{AuthInfo, LoginInfo};

    const HOST1: &str = "http://127.0.0.1";
    const USERNAME1: &str = "username_test1";
    const PASSWORD1: &str = "password_test1";

    const HOST2: &str = "http://172.17.0.1";
    const USERNAME2: &str = "username_test2";
    const PASSWORD2: &str = "password_test2";

    #[test]
    fn test_auth() {
        let url1 = Url::parse(HOST1).unwrap();
        let url2 = Url::parse(HOST2).unwrap();
        let login1 = LoginInfo::new(url1.host_str().unwrap(), USERNAME1, PASSWORD1);
        let login2 = LoginInfo::new(url2.host_str().unwrap(), USERNAME2, PASSWORD2);
        let mut auth = AuthInfo(vec![]);

        auth.set_login_info(login1.clone());
        auth.set_login_info(login2.clone());

        assert_eq!(auth.0.len(), 2);
        assert_eq!(
            auth.get_auth_info_by_url(url2.host_str().unwrap()).unwrap(),
            login2.get_user_pwd().unwrap()
        );
        assert_eq!(
            auth.get_auth_info_by_url(url1.host_str().unwrap()).unwrap(),
            login1.get_user_pwd().unwrap()
        );

        auth.remove_login_info(url2.host_str().unwrap()).unwrap();

        assert_eq!(auth.0.len(), 1);

        assert_eq!(
            auth.get_auth_info_by_url(url1.host_str().unwrap()).unwrap(),
            login1.get_user_pwd().unwrap()
        );
        assert!(auth.get_auth_info_by_url(url2.host_str().unwrap()).is_err());
    }
}
