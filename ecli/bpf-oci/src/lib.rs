//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::collections::HashMap;

pub use oci_distribution;
use oci_distribution::{
    annotations,
    client::{Config, ImageLayer},
    manifest,
    secrets::RegistryAuth,
    Client, Reference,
};

pub mod auth;

#[cfg(test)]
pub(crate) mod tests;

use anyhow::{anyhow, bail, Context, Result};
/// Pull a wasm image from the registry
/// Use the authencation info provided by `auth`
/// Provide your own client if you want to customization
pub async fn pull_wasm_image(
    reference: &Reference,
    auth: &RegistryAuth,
    client: Option<&mut Client>,
) -> Result<Vec<u8>> {
    let mut local_client = Client::default();
    let client = client.unwrap_or(&mut local_client);
    let out = client
        .pull(reference, auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
        .await
        .with_context(|| anyhow!("Failed to poll wasm image"))?
        .layers
        .into_iter()
        .next()
        .map(|v| v.data)
        .with_context(|| anyhow!("Data not found from the image"))?;
    Ok(out)
}

pub async fn push_wasm_image(
    auth: &RegistryAuth,
    reference: &Reference,
    annotations: Option<HashMap<String, String>>,
    module: &[u8],
    client: Option<&mut Client>,
) -> Result<()> {
    let mut local_client = Client::default();
    let client = client.unwrap_or(&mut local_client);
    let layers = vec![ImageLayer::new(
        module.to_vec(),
        manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
        None,
    )];
    let config = Config {
        annotations: None,
        data: b"{}".to_vec(),
        media_type: manifest::WASM_CONFIG_MEDIA_TYPE.to_string(),
    };
    let image_manifest = manifest::OciImageManifest::build(&layers, &config, annotations);
    client
        .push(reference, &layers, config, auth, Some(image_manifest))
        .await
        .with_context(|| anyhow!("Failed to push image"))?;

    Ok(())
}
/// Parse annotations like key=value into HashMap
pub fn parse_annotations<T: AsRef<str>>(input: &[T]) -> anyhow::Result<HashMap<String, String>> {
    let mut annotations_map = HashMap::default();
    for ent in input.iter() {
        if let Some((key, value)) = ent.as_ref().split_once('=') {
            annotations_map.insert(key.into(), value.into());
        } else {
            bail!("Annotations should be like `key=value`");
        }
    }
    Ok(annotations_map)
}
/// Parse annotations like key=value into HashMap
/// Will insert ORG_OPENCONTAINERS_IMAGE_TITLE if not provided
pub fn parse_annotations_and_insert_image_title<T: AsRef<str>>(
    input: &[T],
    title: String,
) -> anyhow::Result<HashMap<String, String>> {
    let mut ret = parse_annotations(input)?;
    if !ret.contains_key(&annotations::ORG_OPENCONTAINERS_IMAGE_TITLE.to_owned()) {
        ret.insert(
            annotations::ORG_OPENCONTAINERS_IMAGE_TITLE.to_string(),
            title,
        );
    }
    Ok(ret)
}
