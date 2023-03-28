//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::collections::HashMap;

use oci_distribution::{
    client::{Config, ImageLayer},
    manifest,
    secrets::RegistryAuth,
    Client, Reference,
};

use crate::error::{EcliError, EcliResult};

/// Configuration for a pushing process
pub struct PushArgs {
    /// Local file path
    pub file: String,
    /// URL to push
    pub image_url: String,
}

// return the manifest url
pub(super) async fn push_wasm_to_registry(
    client: &mut Client,
    auth: &RegistryAuth,
    reference: &Reference,
    module: Vec<u8>,
    annotations: Option<HashMap<String, String>>,
) -> EcliResult<String> {
    let layers = vec![ImageLayer::new(
        module,
        manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
        None,
    )];

    let config = Config {
        data: b"{}".to_vec(),
        media_type: manifest::WASM_CONFIG_MEDIA_TYPE.to_string(),
        annotations: None,
    };

    let image_manifest = manifest::OciImageManifest::build(&layers, &config, annotations);

    let resp = client
        .push(reference, &layers, config, auth, Some(image_manifest))
        .await
        .map_err(|e| EcliError::OciPushError(e.to_string()))?;

    Ok(resp.manifest_url)
}
