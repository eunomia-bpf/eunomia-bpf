//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};

use crate::{
    error::{EcliError, EcliResult},
    Action,
};

pub struct PullArgs {
    pub write_file: String,
    pub image_url: String,
}
impl TryFrom<Action> for PullArgs {
    type Error = EcliError;

    fn try_from(value: Action) -> Result<Self, Self::Error> {
        let Action::Pull { output, image } = value else {
            unreachable!()
        };

        Ok(PullArgs {
            write_file: output,
            image_url: image,
        })
    }
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
