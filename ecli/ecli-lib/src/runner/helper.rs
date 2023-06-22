//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::path::PathBuf;

use ecli_oci::{pull_wasm_image, oci_distribution::{Reference, secrets::RegistryAuth}};
use log::{debug, info};

use crate::{
    config::ProgramType,
    error::{Error, Result},
};

/// Load the binary of the given url, and guess its program type
/// If failed to guess, will just return None
/// It will try the following order
/// - Test if the provided string is a local file. If matches, read it
/// - If the string is a URL, then treat it as a HTTP URL, and download it.
/// - If the string is not an url, treat it as an OCI image tag
pub async fn try_load_program_buf_and_guess_type(
    url: impl AsRef<str>,
) -> Result<(Vec<u8>, Option<ProgramType>)> {
    let url = url.as_ref();
    // Is it a local path?
    let path = PathBuf::from(url);
    let (buf, prog_type) = if path.exists() && path.is_file() {
        debug!("Read from local file: {}", url);
        let buf = tokio::fs::read(path.as_path())
            .await
            .map_err(Error::IOErr)?;
        let prog_type = ProgramType::try_from(url).ok();

        (buf, prog_type)
    } else if let Ok(url) = url::Url::parse(url) {
        debug!("URL parse ok");
        debug!("Download from {:?}", url);
        let resp = reqwest::get(url.clone()).await.map_err(|e| {
            Error::Http(format!("Failed to send request to {}: {}", url.as_str(), e))
        })?;
        let data = resp.bytes().await.map_err(|e| {
            Error::Http(format!(
                "Failed to read response from {}: {}",
                url.as_str(),
                e
            ))
        })?;
        let prog_type = match ProgramType::try_from(url.as_str()) {
            Ok(v) => Some(v),
            Err(e) => {
                info!(
                    "Failed to guess program type from `{}`: {}",
                    url.as_str(),
                    e
                );
                None
            }
        };

        (data.to_vec(), prog_type)
    } else {
        debug!("Trying OCI tag: {}", url);
        let image = Reference::try_from(url).map_err(|e| {
            Error::OciPull(format!(
                "Failed to parse `{}` into an OCI image reference: {}",
                url, e
            ))
        })?;

        let data = pull_wasm_image(&image, &RegistryAuth::Anonymous, None)
            .await
            .map_err(|e| {
                Error::OciPull(format!("Failed to pull OCI image from `{}`: {}", url, e))
            })?;
        (data, Some(ProgramType::WasmModule))
    };
    Ok((buf, prog_type))
}
