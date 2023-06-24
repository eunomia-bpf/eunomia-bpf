use anyhow::{anyhow, Context};
use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand};

use bpf_oci::{
    auth::RegistryAuthExt,
    oci_distribution::{secrets::RegistryAuth, Reference},
    parse_annotations_and_insert_image_title, pull_wasm_image, push_wasm_image,
};
use ecli_lib::error::{Error, Result};
use log::warn;

#[cfg(feature = "http")]
mod http_client;
#[cfg(feature = "native")]
mod native_client;

mod helper;

#[derive(clap::clap_derive::Args)]
struct RunProgArgs {
    /// json output format
    #[arg(
        long,
        short = 'j',
        default_value_t = false,
        help = "Let the ebpf program prints the logs in json format. Only works for JSON program"
    )]
    json: bool,
    /// program path or url
    #[arg(
        allow_hyphen_values = true,
        help = "ebpf program URL or local path, set it `-` to read the program from stdin"
    )]
    prog: String,
    #[arg(help = "Extra args to the program; For wasm program, it will be passed directly to it; For JSON program, it will be passed to the generated argument parser", action = clap::ArgAction::Append)]
    extra_args: Vec<String>,
    #[clap(long, short, help = "Manually specity the program type", value_parser = helper::prog_type_value_parser)]
    prog_type: Option<ecli_lib::config::ProgramType>,
}

#[derive(Parser)]
#[group(multiple = false, required = false)]
pub struct AuthArgs {
    #[arg(
        long,
        short = 'i',
        help = "Prompt the user to input username and password",
        conflicts_with = "UserCredential"
    )]
    prompt: bool,
    #[command(flatten)]
    credential: UserCredential,
}

#[derive(Args)]
#[group(multiple = true)]
pub struct UserCredential {
    #[arg(
        long,
        short,
        help = "Manually specify the username",
        requires = "password"
    )]
    username: Option<String>,
    #[arg(
        long,
        short,
        help = "Manually specify the password",
        requires = "username"
    )]
    password: Option<String>,
}

impl AuthArgs {
    fn load_registry_auth(&self, image: &Reference) -> Result<RegistryAuth> {
        let result = if self.prompt {
            RegistryAuth::load_from_prompt().map_err(|e| Error::IORead(e.to_string()))?
        } else if self.credential.password.is_some() {
            RegistryAuth::Basic(
                self.credential.username.clone().unwrap(),
                self.credential.password.clone().unwrap(),
            )
        } else {
            match RegistryAuth::load_from_docker(None, image.registry()) {
                Err(e) => {
                    warn!(
                        "Failed to read credentials from docker: {}.\
                     Will login to registry anonymously",
                        e
                    );
                    RegistryAuth::Anonymous
                }
                Ok(v) => v,
            }
        };
        Ok(result)
    }
}

#[derive(Parser)]
pub struct OCIArgs {
    /// oci image path
    #[arg(help = "Reference of the image")]
    image: String,
    #[clap(flatten)]
    auth: AuthArgs,
}

impl OCIArgs {
    fn load_registry_auth_and_registry(&self) -> Result<(Reference, RegistryAuth)> {
        let image = Reference::try_from(self.image.as_str()).map_err(|e| {
            Error::InvalidParam(format!(
                "Unable to parse image reference: {} ({})",
                self.image, e
            ))
        })?;
        let auth = self.auth.load_registry_auth(&image)?;
        Ok((image, auth))
    }
}

const AUTH_HELP: &str = "About the authencation:\n\
If neither of -i, -u & -p is provided, will try to read credentials from \
docker's configuration (~/.docker/config.json) and use them to login into the registry. \
If unable to read, will login to the registry anonymously";

/// ecli subcommands, including run, push, pull.
#[derive(Subcommand)]
pub enum Action {
    /// run ebpf program
    #[cfg(feature = "native")]
    Run {
        /// json output format
        #[arg(
            long,
            short = 'j',
            default_value_t = false,
            help = "Let the ebpf program prints the logs in json format. Only works for JSON program"
        )]
        json: bool,
        /// program path or url
        #[arg(
            allow_hyphen_values = true,
            help = "ebpf program URL or local path, set it `-` to read the program from stdin"
        )]
        prog: String,
        #[arg(help = "Extra args to the program; For wasm program, it will be passed directly to it; For JSON program, it will be passed to the generated argument parser", action = clap::ArgAction::Append)]
        extra_args: Vec<String>,
        #[clap(long, short, help = "Manually specity the program type", value_parser = helper::prog_type_value_parser)]
        prog_type: Option<ecli_lib::config::ProgramType>,
    },

    #[cfg(feature = "http")]
    #[clap(name = "client", about = "Client operations")]
    Client(http_client::ClientCmd),
    #[clap(about = "Operations about pushing image to registry", after_help = AUTH_HELP)]
    Push {
        /// wasm module path
        #[arg(long, short, default_value_t = ("app.wasm").to_string(), help = "Path to the wasm module")]
        module: String,
        #[clap(flatten)]
        oci: OCIArgs,

        #[clap(
            short,
            long,
            required = false,
            help = "OCI Annotations to be added to the manifest. Should be like `key=value`"
        )]
        annotations: Vec<String>,
    },
    /// pull oci image from registry
    #[clap(about = "Operations about pulling image from registry", after_help = AUTH_HELP)]
    Pull {
        /// wasm module url
        #[arg(short, long, default_value_t = ("app.wasm").to_string(), help = "Path to the wasm module")]
        output: String,
        #[clap(flatten)]
        oci: OCIArgs,
    },
}

#[derive(Parser)]
struct CliArgs {
    #[command(subcommand)]
    action: Option<Action>,
    /// program path or url
    #[cfg(feature = "native")]
    #[arg(
        allow_hyphen_values = true,
        help = "Not preferred. Only for compatibility to older versions. Ebpf program URL or local path, set it `-` to read the program from stdin"
    )]
    prog: Option<String>,
    #[cfg(feature = "native")]
    #[arg(help = "Not preferred. Only for compatibility to older versions. Extra args to the program; For wasm program, it will be passed directly to it; For JSON program, it will be passed to the generated argument parser", action = clap::ArgAction::Append)]
    extra_args: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")
        .map_err(|e| Error::Log(format!("Failed to create logger: {}", e)))?
        .start()
        .map_err(|e| Error::Log(format!("Failed to start logger: {}", e)))?;

    #[cfg(feature = "native")]
    {
        use std::sync::atomic::Ordering;
        ctrlc::set_handler(move || {
            native_client::TERMINATED.store(true, Ordering::Relaxed);
        })
        .ok();
    }
    let args = CliArgs::parse();

    #[cfg(feature = "native")]
    {
        if let Some(prog) = args.prog {
            native_client::run_native(false, prog, &args.extra_args, None)
                .await
                .with_context(|| anyhow!("Failed to run native eBPF program"))?;
            return Ok(());
        }
    }

    match args.action {
        #[cfg(feature = "native")]
        Some(Action::Run {
            json,
            prog,
            extra_args,
            prog_type,
        }) => native_client::run_native(json, prog, &extra_args, prog_type)
            .await
            .with_context(|| anyhow!("Failed to run native eBPF program")),
        Some(Action::Push {
            module,
            oci,
            annotations,
        }) => {
            let (image, auth) = oci.load_registry_auth_and_registry().with_context(|| {
                anyhow!("Failed to extract RegistryAuth and Reference from args")
            })?;
            let module_bin = tokio::fs::read(&module)
                .await
                .with_context(|| anyhow!("Failed to read module binary"))?;
            let annotations = parse_annotations_and_insert_image_title(&annotations, module)?;

            push_wasm_image(&auth, &image, Some(annotations), &module_bin, None)
                .await
                .with_context(|| anyhow!("Failed to push image"))?;

            Ok(())
        }
        Some(Action::Pull { output, oci }) => {
            let (image, auth) = oci.load_registry_auth_and_registry().with_context(|| {
                anyhow!("Failed to extract RegistryAuth and Reference from args")
            })?;
            let module_bin = pull_wasm_image(&image, &auth, None)
                .await
                .with_context(|| anyhow!("Failed to pull image"))?;
            tokio::fs::write(output, module_bin)
                .await
                .with_context(|| anyhow!("Failed to write module binary to local"))?;
            Ok(())
        }
        #[cfg(feature = "http")]
        Some(Action::Client(cmd)) => http_client::handle_client_command(cmd)
            .await
            .with_context(|| anyhow!("Failed to process client command")),
        None => CliArgs::command()
            .error(
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "Either use subcommand, or directly provide program URL",
            )
            .exit(),
    }
}
