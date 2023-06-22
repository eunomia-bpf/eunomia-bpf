use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand};

use bpf_oci::{
    auth::RegistryAuthExt,
    oci_distribution::{secrets::RegistryAuth, Reference},
    pull_wasm_image, push_wasm_image,
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

    Push {
        /// wasm module path
        #[arg(long, short, default_value_t = ("app.wasm").to_string(), help = "Path to the wasm module")]
        module: String,
        #[clap(flatten)]
        oci: OCIArgs,
    },
    /// pull oci image from registry
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
async fn main() -> Result<()> {
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
            native_client::run_native(false, prog, &args.extra_args, None).await?;
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
        }) => native_client::run_native(json, prog, &extra_args, prog_type).await,
        Some(Action::Push { module, oci }) => {
            let (image, auth) = oci.load_registry_auth_and_registry()?;
            let module_bin = tokio::fs::read(&module).await.map_err(Error::IOErr)?;

            push_wasm_image(&auth, &image, None, &module_bin, None)
                .await
                .map_err(|e| Error::OciPush(e.to_string()))?;

            Ok(())
        }
        Some(Action::Pull { output, oci }) => {
            let (image, auth) = oci.load_registry_auth_and_registry()?;
            let module_bin = pull_wasm_image(&image, &auth, None)
                .await
                .map_err(|e| Error::OciPull(e.to_string()))?;
            tokio::fs::write(output, module_bin)
                .await
                .map_err(Error::IOErr)?;
            Ok(())
        }
        #[cfg(feature = "http")]
        Some(Action::Client(cmd)) => http_client::handle_client_command(cmd).await,
        None => CliArgs::command()
            .error(
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "Either use subcommand, or directly provide program URL",
            )
            .exit(),
    }
}
