//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::io::{stdin, stdout, Write};

use oci_distribution::{secrets::RegistryAuth, Reference, RegistryOperation};
use url::Url;

use crate::{
    error::{EcliError, EcliResult},
    oci::get_client,
};

use super::{get_auth_save_file, AuthInfo, LoginInfo};

fn read_login_user_pwd() -> (String, String) {
    print!("username: ");
    let _ = stdout().flush();
    (
        stdin().lines().next().unwrap().unwrap(),
        rpassword::prompt_password("password: ").unwrap(),
    )
}

pub async fn login(u: String) -> EcliResult<()> {
    let url = Url::parse(u.as_str()).map_err(|e| EcliError::ParamErr(e.to_string()))?;
    let Some(host) = url.host_str() else {
        return Err(EcliError::ParamErr("url format incorrect".to_string()))
    };

    let mut auth_info = AuthInfo::get()?;
    let (username, password) = read_login_user_pwd();
    let login_info = LoginInfo::new(host, username.as_str(), password.as_str());

    v2_login(&url, &login_info).await?;
    auth_info.set_login_info(login_info);
    auth_info.write_to_file(&mut get_auth_save_file()?)?;
    println!("Login success");
    Ok(())
}

async fn v2_login(url: &Url, login_info: &LoginInfo) -> EcliResult<()> {
    let (username, password) = login_info.get_user_pwd()?;
    let mut client = get_client(&url)?;
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
