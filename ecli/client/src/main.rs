use anyhow::{anyhow, Context};
#[cfg(feature = "native")]
use clap::error::ContextKind;
use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand};
use std::ffi::OsString;

use bpf_oci::{
    auth::RegistryAuthExt,
    oci_distribution::{secrets::RegistryAuth, Reference},
    parse_annotations_and_insert_image_title, pull_wasm_image, push_wasm_image,
};
use ecli_lib::error::{Error, Result};
use log::warn;

#[cfg(feature = "native")]
mod native_client;

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

#[cfg(feature = "native")]
const CLI_ABOUT: &str = "ecli subcommands, including run, push, pull";
#[cfg(not(feature = "native"))]
const CLI_ABOUT: &str = "ecli subcommands, including push, pull";
#[cfg(feature = "native")]
const MISSING_SUBCOMMAND_MESSAGE: &str = "Use a subcommand such as `run`, `push`, or `pull`";
#[cfg(not(feature = "native"))]
const MISSING_SUBCOMMAND_MESSAGE: &str = "Use a subcommand such as `push` or `pull`";
#[cfg(feature = "native")]
const LEGACY_RUN_MIGRATION_MESSAGE: &str =
    "The top-level positional run mode has been removed. If you intended to run a program, use `ecli run <program>` instead, for example `ecli run prog` or `ecli run alpine`.";
#[cfg(feature = "native")]
const TOP_LEVEL_SUBCOMMANDS: &[&str] = &["run", "push", "pull", "help"];

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
        #[clap(long, short, help = "Manually specity the program type")]
        prog_type: Option<ecli_lib::config::ProgramType>,
        #[arg(help = "Command line to run. The executable could either be a local path or URL or `-` (read from stdin). The following arguments will be passed to the program", action = clap::ArgAction::Append, allow_hyphen_values = true, required = true)]
        command_line: Vec<String>,
    },

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
#[command(name = "ecli", bin_name = "ecli", about = CLI_ABOUT)]
struct CliArgs {
    #[command(subcommand)]
    action: Option<Action>,
}

#[cfg(feature = "native")]
fn should_suggest_run_migration(raw_args: &[OsString], err: &clap::Error) -> bool {
    is_legacy_run_candidate(raw_args)
        && !has_suggested_subcommand(err)
        && !is_unsuggested_run_typo(raw_args)
}

#[cfg(feature = "native")]
fn is_legacy_run_candidate(raw_args: &[OsString]) -> bool {
    let Some(first_arg) = raw_args.get(1).and_then(|arg| arg.to_str()) else {
        return false;
    };
    if first_arg.starts_with('-') && first_arg != "-" {
        return false;
    }
    !TOP_LEVEL_SUBCOMMANDS.contains(&first_arg)
}

#[cfg(feature = "native")]
fn is_unsuggested_run_typo(raw_args: &[OsString]) -> bool {
    let Some(first_arg) = raw_args.get(1).and_then(|arg| arg.to_str()) else {
        return false;
    };

    // Keep ambiguous one-edit names like `rn` on the legacy migration path, but
    // let broader two-edit `run` misspellings fall through to Clap's error.
    is_within_edit_distance(first_arg, "run", 2) && !is_within_edit_distance(first_arg, "run", 1)
}

#[cfg(feature = "native")]
fn is_within_edit_distance(lhs: &str, rhs: &str, max_distance: usize) -> bool {
    let lhs = lhs.as_bytes();
    let rhs = rhs.as_bytes();
    if lhs.len().abs_diff(rhs.len()) > max_distance {
        return false;
    }

    let mut prev_prev = vec![0; rhs.len() + 1];
    let mut prev = (0..=rhs.len()).collect::<Vec<_>>();
    let mut curr = vec![0; rhs.len() + 1];

    for (i, &lhs_byte) in lhs.iter().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];

        for (j, &rhs_byte) in rhs.iter().enumerate() {
            let substitution_cost = usize::from(lhs_byte != rhs_byte);
            let mut cost = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + substitution_cost);

            if i > 0 && j > 0 && lhs_byte == rhs[j - 1] && lhs[i - 1] == rhs_byte {
                cost = cost.min(prev_prev[j - 1] + 1);
            }

            curr[j + 1] = cost;
            row_min = row_min.min(cost);
        }

        if row_min > max_distance {
            return false;
        }

        std::mem::swap(&mut prev_prev, &mut prev);
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[rhs.len()] <= max_distance
}

#[cfg(not(feature = "native"))]
#[allow(dead_code)]
fn is_legacy_run_candidate(_raw_args: &[OsString]) -> bool {
    false
}

#[cfg(feature = "native")]
fn has_suggested_subcommand(err: &clap::Error) -> bool {
    err.get(ContextKind::SuggestedSubcommand).is_some()
}

#[cfg(not(feature = "native"))]
#[allow(dead_code)]
fn should_suggest_run_migration(_raw_args: &[OsString]) -> bool {
    false
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
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    let args = match CliArgs::try_parse_from(raw_args.clone()) {
        Ok(args) => args,
        Err(err) => {
            #[cfg(feature = "native")]
            if err.kind() == ErrorKind::InvalidSubcommand
                && should_suggest_run_migration(&raw_args, &err)
            {
                CliArgs::command()
                    .error(ErrorKind::InvalidSubcommand, LEGACY_RUN_MIGRATION_MESSAGE)
                    .exit();
            }
            err.exit();
        }
    };

    match args.action {
        #[cfg(feature = "native")]
        Some(Action::Run {
            json,
            command_line,
            prog_type,
        }) => {
            let (prog, args) = command_line.split_first().unwrap();
            native_client::run_native(json, prog.to_string(), args, prog_type)
                .await
                .with_context(|| anyhow!("Failed to run native eBPF program"))
        }
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
        None => CliArgs::command()
            .error(
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                MISSING_SUBCOMMAND_MESSAGE,
            )
            .exit(),
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    #[cfg(feature = "native")]
    use ecli_lib::config::ProgramType;

    #[cfg(feature = "native")]
    use super::Action;
    use super::CliArgs;
    #[cfg(feature = "native")]
    use std::ffi::OsString;

    #[test]
    fn reject_legacy_top_level_run_shim() {
        assert!(CliArgs::try_parse_from(["ecli", "./prog.json"]).is_err());
    }

    #[cfg(feature = "native")]
    #[test]
    fn top_level_help_mentions_run_when_native_enabled() {
        let help = CliArgs::command().render_help().to_string();

        assert!(help.contains("ecli subcommands, including run, push, pull"));
        assert!(help.contains("\n  run "));
    }

    #[cfg(not(feature = "native"))]
    #[test]
    fn top_level_help_omits_run_when_native_disabled() {
        let help = CliArgs::command().render_help().to_string();

        assert!(help.contains("ecli subcommands, including push, pull"));
        assert!(!help.contains("\n  run "));
    }

    #[cfg(feature = "native")]
    #[test]
    fn missing_subcommand_message_mentions_run_when_native_enabled() {
        assert_eq!(
            super::MISSING_SUBCOMMAND_MESSAGE,
            "Use a subcommand such as `run`, `push`, or `pull`"
        );
    }

    #[cfg(not(feature = "native"))]
    #[test]
    fn missing_subcommand_message_omits_run_when_native_disabled() {
        assert_eq!(
            super::MISSING_SUBCOMMAND_MESSAGE,
            "Use a subcommand such as `push` or `pull`"
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn suggest_run_migration_for_legacy_program_argument() {
        for arg in [
            "./prog.json",
            "ghcr.io/eunomia-bpf/execve:latest",
            "prog",
            "alpine",
            "rn",
            "un",
            "rnu",
            "urn",
        ] {
            let raw_args = vec![OsString::from("ecli"), OsString::from(arg)];
            let err = match CliArgs::try_parse_from(raw_args.clone()) {
                Ok(_) => panic!("expected parse error"),
                Err(err) => err,
            };

            assert!(super::should_suggest_run_migration(&raw_args, &err));
            assert!(!super::has_suggested_subcommand(&err));
        }
    }

    #[test]
    fn do_not_treat_real_subcommands_or_flags_as_legacy_run_candidates() {
        assert!(!super::is_legacy_run_candidate(&[
            "ecli".into(),
            "push".into()
        ]));
        assert!(!super::is_legacy_run_candidate(&[
            "ecli".into(),
            "--help".into()
        ]));
    }

    #[cfg(feature = "native")]
    #[test]
    fn do_not_suggest_run_migration_for_subcommand_typos() {
        for typo in [
            "pus", "pll", "runn", "psuh", "psu", "plu", "pushhhh", "runnnn",
        ] {
            let raw_args = vec![OsString::from("ecli"), OsString::from(typo)];
            let err = match CliArgs::try_parse_from(raw_args.clone()) {
                Ok(_) => panic!("expected parse error"),
                Err(err) => err,
            };

            assert!(!super::should_suggest_run_migration(&raw_args, &err));
            assert!(super::has_suggested_subcommand(&err));
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn do_not_suggest_run_migration_for_unsuggested_run_typos() {
        for typo in ["ur", "nru", "rn-", "nnrun"] {
            let raw_args = vec![OsString::from("ecli"), OsString::from(typo)];
            let err = match CliArgs::try_parse_from(raw_args.clone()) {
                Ok(_) => panic!("expected parse error"),
                Err(err) => err,
            };

            assert!(!super::should_suggest_run_migration(&raw_args, &err));
            assert!(!super::has_suggested_subcommand(&err));
        }
    }

    #[cfg(not(feature = "native"))]
    #[test]
    fn no_native_build_does_not_offer_run_migration() {
        assert!(!super::should_suggest_run_migration(&[
            "ecli".into(),
            "./prog.json".into(),
        ]));
    }

    #[cfg(feature = "native")]
    #[test]
    fn parse_run_subcommand_program_type_alias() {
        let args =
            CliArgs::try_parse_from(["ecli", "run", "--prog-type", "json", "./prog.json"]).unwrap();

        match args.action {
            Some(Action::Run {
                prog_type,
                command_line,
                ..
            }) => {
                assert_eq!(prog_type, Some(ProgramType::JsonEunomia));
                assert_eq!(command_line, vec!["./prog.json".to_string()]);
            }
            _ => panic!("expected run action"),
        }
    }
}
