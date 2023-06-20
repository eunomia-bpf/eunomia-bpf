//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::path::Path;

use log::{debug, info};
use oci_distribution::{secrets::RegistryAuth, Client, Reference};
use tokio::{fs::File, io::AsyncReadExt};
use url::Url;

use crate::{
    error::{Error, Result},
    oci::wasm::pull::pull_wasm_from_registry,
};

use self::push::push_wasm_to_registry;

use super::{auth::get_auth_info_by_url, default_schema_port, get_client};

/// Module containing stuff related to pulling image
pub mod pull;
/// Module containing stuff related to pushing image
pub mod push;

/// Parse the URL, return things that will be used for pushing / pulling
/// returns (..., repo_url_strip_auth_info)
pub fn parse_img_url(url: &str) -> Result<(Client, RegistryAuth, Reference, String)> {
    let img_url = Url::parse(url).map_err(|e| Error::InvalidParam(e.to_string()))?;
    let auth = match get_auth_info_by_url(&img_url) {
        Ok((username, password)) => {
            println!("auth with username: {}", username);
            RegistryAuth::Basic(username, password)
        }
        Err(err) => {
            if matches!(err, Error::LoginInfoNotFound(_)) {
                RegistryAuth::Anonymous
            } else {
                return Err(err);
            }
        }
    };
    debug!("Parsed auth info: {:?}", auth);
    let client = get_client(&img_url)?;
    let Some(host) = img_url.host() else {
        return Err(Error::InvalidParam(format!("invalid url: {}",url)))
    };

    let repo_url = format!(
        "{}:{}{}",
        host,
        img_url
            .port()
            .unwrap_or(default_schema_port(img_url.scheme())?),
        img_url.path()
    );

    Ok((
        client,
        auth,
        repo_url
            .parse::<Reference>()
            .map_err(|e| Error::InvalidParam(e.to_string()))?,
        repo_url,
    ))
}

/// Push an image
pub async fn wasm_push(file: String, img_url: String) -> Result<()> {
    // TODO check the file is valid wasm file
    let path = Path::new(file.as_str());
    let mut module = vec![];
    if path.exists() && path.is_file() {
        info!("read content from file {}", file);
        let mut f = File::open(path).await.map_err(Error::IOErr)?;
        f.read_to_end(&mut module).await.map_err(Error::IOErr)?;
    } else {
        return Err(Error::InvalidParam(format!(
            "file {} not exist or is not regular file",
            file
        )));
    }

    let (mut client, auth, reference, repo_url) = parse_img_url(img_url.as_str())?;

    info!("pushing to {}", repo_url);
    let url = push_wasm_to_registry(&mut client, &auth, &reference, module, None).await?;
    info!("successful push to {}", repo_url);

    println!("successfully push to to {}", url);
    Ok(())
}

/// Pull an image
pub async fn wasm_pull(img: &str) -> Result<Vec<u8>> {
    let (mut client, auth, reference, repo_url) = parse_img_url(img)?;
    info!("pulling from {}", repo_url);
    let img_content = pull_wasm_from_registry(&mut client, &auth, &reference).await?;
    info!(
        "successful pull {} bytes from {}",
        img_content.len(),
        repo_url
    );
    // TODO check the pull data is valid wasm file
    Ok(img_content)
}
