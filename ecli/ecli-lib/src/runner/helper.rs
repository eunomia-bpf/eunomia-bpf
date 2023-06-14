//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::path::PathBuf;

use log::debug;

use crate::{
    config::ProgramType,
    error::{Error, Result},
    oci::{default_schema_port, wasm_pull},
};

/// Load the binary of the given url, and guess its program type
/// If failed to guess, will just return None
/// It will try the following order
/// - Test if the provided url is indicates a local file, if matches, read that and treat it as a JSON or TAR
/// - Test if the provided url points to a HTTP/HTTPS file. If matches, download that and treat it as a JSON or TAR
/// - Otherwise, treat the given URL as a OCI image
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
        debug!(
            "try read content from url: {}",
            format!(
                "{}://{}:{}{}?{}",
                url.scheme(),
                if let Some(host) = url.host() {
                    host.to_string()
                } else {
                    return Err(Error::UnknownFileType(format!(
                        "unknown type of {}, must file path or valid url",
                        url.as_str()
                    )));
                },
                url.port().unwrap_or(default_schema_port(url.scheme())?),
                url.path(),
                url.query().unwrap_or_default()
            )
        );
        let buf = reqwest::get(url.as_str())
            .await
            .map_err(|e| Error::Http(format!("Failed to download `{}`: {}", url.as_str(), e)))?
            .bytes()
            .await
            .map_err(|e| Error::Other(format!("Failed to read bytes: {}", e)))?
            .to_vec();
        let prog_type = ProgramType::try_from(url.path()).ok();
        (buf, prog_type)
    } else {
        debug!("Read from OCI repo url: {}", url);
        let buf = wasm_pull(url)
            .await
            .map_err(|e| Error::Http(format!("Failed to poll image from `{}`: {}", url, e)))?;

        (buf, Some(ProgramType::WasmModule))
    };
    Ok((buf, prog_type))
}
