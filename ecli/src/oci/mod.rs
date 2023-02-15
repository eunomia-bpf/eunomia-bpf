//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
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
pub use wasm::{parse_img_url, wasm_pull};

use crate::error::{EcliError, EcliResult};

use wasm::wasm_push;

use self::wasm::{pull::PullArgs, push::PushArgs};

pub fn default_schema_port(schema: &str) -> EcliResult<u16> {
    match schema {
        "http" => Ok(80),
        "https" => Ok(443),
        _ => Err(EcliError::ParamErr(format!("unknown schema {}", schema))),
    }
}

pub fn get_client(url: &Url) -> EcliResult<Client> {
    Ok(Client::new(ClientConfig {
        protocol: match url.scheme() {
            "http" => ClientProtocol::Http,
            "https" => ClientProtocol::Https,
            _ => {
                return Err(EcliError::ParamErr(format!(
                    "unsupport schema {}",
                    url.scheme()
                )))
            }
        },

        // TODO add self sign cert support
        ..Default::default()
    }))
}

pub async fn push(args: PushArgs) -> EcliResult<()> {
    wasm_push(args.file, args.image_url).await
}

pub async fn pull(args: PullArgs) -> EcliResult<()> {
    let path = Path::new(args.write_file.as_str());
    let mut file = if !path.exists() {
        info!("create file {}", args.write_file);
        File::create(args.write_file.as_str())
            .await
            .map_err(|e| EcliError::IOErr(e))?
    } else if path.is_file() {
        info!("open file {}", args.write_file);
        OpenOptions::new()
            .write(true)
            .open(args.write_file.as_str())
            .await
            .map_err(|e| EcliError::IOErr(e))?
    } else {
        return Err(EcliError::ParamErr(format!(
            "{} is not a regular file",
            args.image_url
        )));
    };

    let data = wasm_pull(args.image_url.as_str()).await?;

    info!("writting wasm data to file {}", args.write_file);
    file.write_all(&data)
        .await
        .map_err(|e| EcliError::IOErr(e))?;
    file.flush().await.map_err(|e| EcliError::IOErr(e))?;
    info!("successful writting wasm data to file {}", args.write_file);
    Ok(())
}
