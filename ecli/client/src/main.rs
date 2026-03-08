use anyhow::{anyhow, Context};
#[cfg(feature = "native")]
use clap::error::{ContextKind, ContextValue};
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
        && !has_non_run_subcommand_suggestion(err)
        && !is_clear_run_command_typo(raw_args)
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
fn is_clear_run_command_typo(raw_args: &[OsString]) -> bool {
    let Some(first_arg) = raw_args.get(1).and_then(|arg| arg.to_str()) else {
        return false;
    };
    if first_arg != "run" && first_arg.eq_ignore_ascii_case("run") {
        return true;
    }

    let first_arg = first_arg.to_ascii_lowercase();
    let collapsed = collapse_adjacent_duplicate_chars(&first_arg);
    // Only suppress the migration hint for command-shaped tokens that are still
    // unmistakably derived from `run`, such as repeated-character variants,
    // those same repeated-character variants plus one trailing junk char,
    // `nnrun`, or the harder two-swap permutations. General legacy
    // program/image names like `bun`, `ru`, `ur`, `rnu`, `urn`, and `runner`
    // should keep the migration guidance.
    matches!(first_arg.as_str(), "nru" | "unr" | "nur")
        || is_run_with_single_inserted_char(&first_arg)
        || is_run_with_single_inserted_char(&collapsed)
        || is_repeated_run_char_typo(&first_arg)
        || has_repeated_run_char_typo_with_trailing_junk(&first_arg)
}

#[cfg(feature = "native")]
fn is_run_with_single_inserted_char(candidate: &str) -> bool {
    if !candidate.starts_with('r') || candidate.chars().count() != 4 {
        return false;
    }

    candidate.char_indices().any(|(idx, ch)| {
        let next = idx + ch.len_utf8();
        let mut without_char = String::with_capacity(candidate.len() - ch.len_utf8());
        without_char.push_str(&candidate[..idx]);
        without_char.push_str(&candidate[next..]);
        without_char == "run"
    })
}

#[cfg(feature = "native")]
fn is_repeated_run_char_sequence(candidate: &str) -> bool {
    if candidate.chars().count() <= 3 || !candidate.chars().all(|ch| matches!(ch, 'r' | 'u' | 'n'))
    {
        return false;
    }

    collapse_adjacent_duplicate_chars(candidate) == "run"
}

#[cfg(feature = "native")]
fn is_repeated_run_char_omission(candidate: &str) -> bool {
    if candidate.chars().count() < 3 || !candidate.chars().all(|ch| matches!(ch, 'r' | 'u' | 'n')) {
        return false;
    }

    let collapsed = collapse_adjacent_duplicate_chars(candidate);
    collapsed.chars().count() == 2 && is_ordered_run_subsequence(&collapsed)
}

#[cfg(feature = "native")]
fn collapse_adjacent_duplicate_chars(candidate: &str) -> String {
    let mut collapsed = String::with_capacity(candidate.len());
    let mut previous = None;
    for ch in candidate.chars() {
        if Some(ch) != previous {
            collapsed.push(ch);
            previous = Some(ch);
        }
    }

    collapsed
}

#[cfg(feature = "native")]
fn is_ordered_run_subsequence(candidate: &str) -> bool {
    let mut run_chars = "run".chars();
    candidate
        .chars()
        .all(|ch| run_chars.by_ref().any(|run_ch| run_ch == ch))
}

#[cfg(feature = "native")]
fn is_repeated_run_char_typo(candidate: &str) -> bool {
    is_repeated_run_char_sequence(candidate)
        || is_repeated_run_char_omission(candidate)
        || has_repeated_run_char_prefix(candidate)
}

#[cfg(feature = "native")]
fn has_repeated_run_char_prefix(candidate: &str) -> bool {
    let Some(prefix) = candidate.strip_suffix("run") else {
        return false;
    };
    if prefix.is_empty() {
        return false;
    }

    let mut chars = prefix.chars();
    let first = chars.next().unwrap();
    matches!(first, 'r' | 'u' | 'n') && chars.all(|ch| ch == first)
}

#[cfg(feature = "native")]
fn has_repeated_run_char_typo_with_trailing_junk(candidate: &str) -> bool {
    let Some((last_idx, last_char)) = candidate.char_indices().last() else {
        return false;
    };
    if last_idx == 0 || matches!(last_char, 'r' | 'u' | 'n') {
        return false;
    }

    is_repeated_run_char_typo(&candidate[..last_idx])
}

#[cfg(feature = "native")]
fn has_non_run_subcommand_suggestion(err: &clap::Error) -> bool {
    suggested_subcommands(err)
        .map(|suggestions| suggestions.iter().any(|suggestion| suggestion != "run"))
        .unwrap_or(false)
}

#[cfg(not(feature = "native"))]
#[allow(dead_code)]
fn is_legacy_run_candidate(_raw_args: &[OsString]) -> bool {
    false
}

#[cfg(all(feature = "native", test))]
fn has_suggested_subcommand(err: &clap::Error) -> bool {
    suggested_subcommands(err).is_some()
}

#[cfg(feature = "native")]
fn suggested_subcommands(err: &clap::Error) -> Option<&[String]> {
    match err.get(ContextKind::SuggestedSubcommand) {
        Some(ContextValue::String(suggestion)) => Some(std::slice::from_ref(suggestion)),
        Some(ContextValue::Strings(suggestions)) => Some(suggestions.as_slice()),
        _ => None,
    }
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

    #[cfg(feature = "native")]
    #[test]
    fn suggest_run_migration_for_legacy_program_names_near_run() {
        for (arg, clap_suggests_run) in
            [("bun", true), ("ru", true), ("ur", false), ("runner", true)]
        {
            let raw_args = vec![OsString::from("ecli"), OsString::from(arg)];
            let err = match CliArgs::try_parse_from(raw_args.clone()) {
                Ok(_) => panic!("expected parse error"),
                Err(err) => err,
            };

            assert!(super::should_suggest_run_migration(&raw_args, &err));
            assert_eq!(super::has_suggested_subcommand(&err), clap_suggests_run);
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
            "pus", "pll", "rrn", "runn", "runn-", "runn1", "ruun", "runx", "run-", "psuh", "psu",
            "plu", "pushhhh", "runnnn", "rrn-", "rrn1", "rnn-", "rnn1", "nnrun-", "nnrun1",
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
        for typo in ["nru", "unr", "nur", "nnrun"] {
            let raw_args = vec![OsString::from("ecli"), OsString::from(typo)];
            let err = match CliArgs::try_parse_from(raw_args.clone()) {
                Ok(_) => panic!("expected parse error"),
                Err(err) => err,
            };

            assert!(!super::should_suggest_run_migration(&raw_args, &err));
            assert!(!super::has_suggested_subcommand(&err));
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn do_not_suggest_run_migration_for_case_only_run_typos() {
        for typo in ["Run", "RUN", "rUn"] {
            let raw_args = vec![OsString::from("ecli"), OsString::from(typo)];
            let err = match CliArgs::try_parse_from(raw_args.clone()) {
                Ok(_) => panic!("expected parse error"),
                Err(err) => err,
            };
            let rendered = err.to_string();

            assert!(!super::should_suggest_run_migration(&raw_args, &err));
            assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
            assert!(rendered.contains(&format!("unrecognized subcommand '{}'", typo)));
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
