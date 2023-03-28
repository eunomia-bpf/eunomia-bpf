//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};

use crate::error::{EcliError, EcliResult};

pub struct PullArgs {
    pub write_file: String,
    pub image_url: String,
}

pub(super) async fn pull_wasm_from_registry(
    client: &mut Client,
    auth: &RegistryAuth,
    reference: &Reference,
) -> EcliResult<Vec<u8>> {
    if let Some(img_data) = client
        .pull(reference, auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
        .await
        .map_err(|e| EcliError::OciPullError(e.to_string()))?
        .layers
        .into_iter()
        .next()
        .map(|layer| layer.data)
    {
        Ok(img_data)
    } else {
        let repo_url = format!(
            "{}/{}:{}",
            reference.registry(),
            reference.repository(),
            reference.tag().unwrap_or("latest"),
        );
        Err(EcliError::OciPullError(format!(
            "no data found in url: {}",
            repo_url
        )))
    }
}
