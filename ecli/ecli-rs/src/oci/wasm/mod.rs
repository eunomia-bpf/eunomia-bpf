use std::path::Path;

use log::info;
use oci_distribution::{
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
    Client, Reference,
};
use tokio::{fs::File, io::AsyncReadExt};
use url::Url;

use crate::{
    error::{EcliError, EcliResult},
    oci::wasm::pull::pull_wasm_from_registry,
};

use self::push::push_wasm_to_registry;

use super::default_schema_port;

pub mod pull;
pub mod push;

// return (..., repo_url_strip_auth_info)
pub fn parse_img_url(url: &str) -> EcliResult<(Client, RegistryAuth, Reference, String)> {
    let img_url = Url::parse(url).map_err(|e| EcliError::ParamErr(e.to_string()))?;
    let auth = if !img_url.username().is_empty() {
        println!("auth with username: {}", img_url.username());
        RegistryAuth::Basic(
            img_url.username().into(),
            img_url.password().unwrap_or_default().into(),
        )
    } else {
        RegistryAuth::Anonymous
    };
    let client = Client::new(ClientConfig {
        protocol: match img_url.scheme() {
            "http" => ClientProtocol::Http,
            "https" => ClientProtocol::Https,
            _ => {
                return Err(EcliError::ParamErr(format!(
                    "unsupport schema {}",
                    img_url.scheme()
                )))
            }
        },

        // TODO add self sign cert support
        ..Default::default()
    });

    let Some(host) = img_url.host() else {
        return Err(EcliError::ParamErr(format!("invalid url: {}",url)))
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
            .map_err(|e| EcliError::ParamErr(e.to_string()))?,
        repo_url.into(),
    ))
}

pub async fn wasm_push(file: String, img_url: String) -> EcliResult<()> {
    // TODO check the file is valid wasm file
    let path = Path::new(file.as_str());
    let mut module = vec![];
    if path.exists() && path.is_file() {
        info!("read content from file {}", file);
        let mut f = File::open(path).await.map_err(|e| EcliError::IOErr(e))?;
        f.read_to_end(&mut module)
            .await
            .map_err(|e| EcliError::IOErr(e))?;
    } else {
        return Err(EcliError::ParamErr(format!(
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

pub async fn wasm_pull(img: &str) -> EcliResult<Vec<u8>> {
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
