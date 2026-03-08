//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use anyhow::anyhow;
use anyhow::Context;
use bpf_oci::{
    oci_distribution::{secrets::RegistryAuth, Reference},
    pull_wasm_image,
};
use log::{debug, info};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

use crate::{
    config::ProgramType,
    error::{Error, Result},
};

/// Load a program from stdin, file path, HTTP URL, or OCI image reference and
/// resolve its type from the user override or the guessed value.
pub async fn load_program_buf_and_guess_type(
    source: impl AsRef<str>,
    user_prog_type: Option<ProgramType>,
) -> anyhow::Result<(Vec<u8>, ProgramType)> {
    let source = source.as_ref();
    if source == "-" {
        let prog_type = user_prog_type.ok_or_else(|| {
            Error::InvalidParam(
                "You must manually specify the -p argument when reading program from stdio"
                    .to_string(),
            )
        })?;
        return Ok((read_stdio_input().await?, prog_type));
    }

    let (buf, guessed_prog_type) = try_load_program_buf_and_guess_type(source).await?;
    let prog_type = user_prog_type.or(guessed_prog_type).ok_or_else(|| {
        Error::InvalidParam(
            "Failed to guess the program type, please specify it through -p argument".to_string(),
        )
    })?;
    Ok((buf, prog_type))
}

pub async fn read_stdio_input() -> Result<Vec<u8>> {
    let mut result = vec![];
    tokio::io::stdin()
        .read_to_end(&mut result)
        .await
        .map_err(Error::IOErr)?;
    Ok(result)
}

/// Load the binary of the given url, and guess its program type
/// If failed to guess, will just return None
/// It will try the following order
/// - Test if the provided string is a local file. If matches, read it
/// - If the string is a URL, then treat it as a HTTP URL, and download it.
/// - If the string is not an url, treat it as an OCI image tag
pub async fn try_load_program_buf_and_guess_type(
    url: impl AsRef<str>,
) -> anyhow::Result<(Vec<u8>, Option<ProgramType>)> {
    let url = url.as_ref();
    // Is it a local path?
    let path = PathBuf::from(url);
    let (buf, prog_type) = if path.exists() && path.is_file() {
        debug!("Read from local file: {}", url);
        let buf = tokio::fs::read(path.as_path())
            .await
            .with_context(|| anyhow!("Failed to read local file: {}", url))?;
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
        let image = Reference::try_from(url)
            .with_context(|| anyhow!("Failed to parse `{}` into an OCI image reference", url))?;

        let data = pull_wasm_image(&image, &RegistryAuth::Anonymous, None)
            .await
            .with_context(|| anyhow!("Failed to pull OCI image from `{}`", url))?;
        (data, Some(ProgramType::WasmModule))
    };
    Ok((buf, prog_type))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::load_program_buf_and_guess_type;
    use crate::config::ProgramType;

    #[tokio::test]
    async fn load_local_program_and_guess_type() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bootstrap.wasm");
        let (buf, prog_type) = load_program_buf_and_guess_type(path.to_str().unwrap(), None)
            .await
            .unwrap();

        assert!(!buf.is_empty());
        assert_eq!(prog_type, ProgramType::WasmModule);
    }

    #[tokio::test]
    async fn explicit_program_type_overrides_guess() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bootstrap.wasm");
        let (_, prog_type) =
            load_program_buf_and_guess_type(path.to_str().unwrap(), Some(ProgramType::JsonEunomia))
                .await
                .unwrap();

        assert_eq!(prog_type, ProgramType::JsonEunomia);
    }

    #[tokio::test]
    async fn stdin_requires_explicit_program_type() {
        let err = load_program_buf_and_guess_type("-", None)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("manually specify the -p argument"));
    }
}
