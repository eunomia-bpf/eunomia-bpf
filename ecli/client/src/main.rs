use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};

use ecli_lib::{
    error::{Error, Result},
    oci::{
        auth::{login, logout},
        pull, push, PullArgs, PushArgs,
    },
};

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

/// ecli subcommands, including run, push, pull, login, logout.
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
        /// oci image path
        #[arg(help = "Image URL")]
        image: String,
    },
    /// pull oci image from registry
    Pull {
        /// wasm module url
        #[arg(short, long, default_value_t = ("app.wasm").to_string(), help = "Path to the wasm module")]
        output: String,
        /// oci image url
        #[arg(help = "Image URL")]
        image: String,
    },
    /// login to oci registry
    Login {
        /// oci login url
        #[arg(default_value_t = ("https://ghcr.io").to_string(), help = "Login URL")]
        url: String,
    },
    /// logout from registry
    Logout {
        /// oci logout url
        #[arg(default_value_t = ("ghcr.io").to_string(), help = "Logout URL")]
        url: String,
    },
}

#[derive(Parser)]
struct Args {
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
    let args = Args::parse();

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
        Some(Action::Push { image, module }) => {
            push(PushArgs {
                file: module,
                image_url: image,
            })
            .await
        }
        Some(Action::Pull { image, output }) => {
            pull(PullArgs {
                write_file: output,
                image_url: image,
            })
            .await
        }
        Some(Action::Login { url }) => login(url).await,
        Some(Action::Logout { url }) => logout(url),
        #[cfg(feature = "http")]
        Some(Action::Client(cmd)) => http_client::handle_client_command(cmd).await,
        None => Args::command()
            .error(
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "Either use subcommand, or directly provide program URL",
            )
            .exit(),
    }
}
