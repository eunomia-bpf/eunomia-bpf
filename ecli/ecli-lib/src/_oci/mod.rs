//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
/// Authencation related stuff
pub mod auth;
mod wasm;

use std::path::Path;

use log::info;
use oci_distribution::{
    client::{ClientConfig, ClientProtocol},
    Client,
};
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
};
use url::Url;
/// Ex-export some helper functions from wasm module
pub use wasm::{parse_img_url, wasm_pull};

use crate::error::{Error, Result};

use wasm::wasm_push;

pub use self::wasm::{pull::PullArgs, push::PushArgs};

/// A helper function to get the default port for http or https
pub fn default_schema_port(schema: &str) -> Result<u16> {
    match schema {
        "http" => Ok(80),
        "https" => Ok(443),
        _ => Err(Error::InvalidParam(format!("unknown schema {}", schema))),
    }
}

/// Create a HTTP client for the given url
pub fn get_client(url: &Url) -> Result<Client> {
    Ok(Client::new(ClientConfig {
        protocol: match url.scheme() {
            "http" => ClientProtocol::Http,
            "https" => ClientProtocol::Https,
            _ => {
                return Err(Error::InvalidParam(format!(
                    "unsupport schema {}",
                    url.scheme()
                )))
            }
        },

        // TODO add self sign cert support
        ..Default::default()
    }))
}

/// Push an image to the OCI registry
pub async fn push(args: PushArgs) -> Result<()> {
    wasm_push(args.file, args.image_url).await
}

/// Pull an image from the registry
pub async fn pull(args: PullArgs) -> Result<()> {
    let path = Path::new(args.write_file.as_str());
    let mut file = if !path.exists() {
        info!("create file {}", args.write_file);
        File::create(args.write_file.as_str())
            .await
            .map_err(Error::IOErr)?
    } else if path.is_file() {
        info!("open file {}", args.write_file);
        OpenOptions::new()
            .write(true)
            .open(args.write_file.as_str())
            .await
            .map_err(Error::IOErr)?
    } else {
        return Err(Error::InvalidParam(format!(
            "{} is not a regular file",
            args.image_url
        )));
    };

    let data = wasm_pull(args.image_url.as_str()).await?;

    info!("writting wasm data to file {}", args.write_file);
    file.write_all(&data).await.map_err(Error::IOErr)?;
    file.flush().await.map_err(Error::IOErr)?;
    info!("successful writting wasm data to file {}", args.write_file);
    Ok(())
}
