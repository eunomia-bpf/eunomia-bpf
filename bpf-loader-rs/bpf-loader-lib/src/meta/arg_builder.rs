use anyhow::{bail, Result};
use clap::{Arg, ArgAction, Command};
use serde_json::Value;

use super::EunomiaObjectMeta;

const DEFAULT_DESCRIPTION: &str = "A simple eBPF program";
const DEFAULT_VERSION: &str = "0.1.0";
const DEFAULT_EPILOG: &str = "Built with eunomia-bpf framework.\nSee https://github.com/eunomia-bpf/eunomia-bpf for more information.";

impl EunomiaObjectMeta {
    /// Build an argument parser use the `cmdarg` sections in .rodata/.bss variables.
    ///
    /// Each variable in the `.bss` or `.rodata` sections will be mapped into a command line argument.
    ///
    /// If a variable has it's default value, the default value will be used in the command line parser.
    ///
    /// Variables with `bool` will have some special cases:
    /// - If the variable has no default values, a switch named `--<NAME>` will be added, indicating to set the value to true or false
    /// - If the default value if true, a switch named `--disable-<NAME>` will be added, means set the value to false
    /// - If the default value if false, a switch named `--enable-<NAME>` will be added, means to set the value to true.
    ///
    /// The first will be used to set the value of the variable to `true`, second one will be used to set `false`
    ///
    /// Variables with other types will accept values. But values will be checked in `parse_arguments_and_fill_skeleton_variables`, so here the values input in the command line parser will be regarded as strings.
    pub fn build_argument_parser(&self) -> Result<Command> {
        let cmd = Command::new(self.bpf_skel.obj_name.to_string());

        let cmd = if let Some(doc) = &self.bpf_skel.doc {
            cmd.version(
                doc.version
                    .to_owned()
                    .unwrap_or(DEFAULT_VERSION.to_string()),
            )
            .after_help(doc.details.to_owned().unwrap_or(DEFAULT_EPILOG.to_owned()))
            .before_help(
                doc.brief
                    .to_owned()
                    .or(doc.description.to_owned())
                    .unwrap_or(DEFAULT_DESCRIPTION.to_owned()),
            )
        } else {
            cmd.version(DEFAULT_VERSION)
                .after_help(DEFAULT_EPILOG)
                .before_help(DEFAULT_DESCRIPTION)
        };
        // Add a switch to control whether to show debug information
        let mut cmd = cmd.arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Whether to show libbpf debug information"),
        );
        // Add arguments for section vars
        for section in self.bpf_skel.data_sections.iter() {
            for variable in section.variables.iter() {
                // Ignore useless variables
                if variable.name.starts_with("__eunomia_dummy") {
                    continue;
                }
                let help = variable
                    .cmdarg
                    .help
                    .to_owned()
                    .or(variable.description.to_owned())
                    .unwrap_or(format!(
                        "Set value of `{}` variable {}",
                        variable.ty, variable.name
                    ));

                let long = variable
                    .cmdarg
                    .long
                    .to_owned()
                    .unwrap_or_else(|| variable.name.to_string());
                if variable.ty == "bool" {
                    // If there is default values
                    let default = if let Some(val) = variable
                        .cmdarg
                        .default
                        .to_owned()
                        .or(variable.value.to_owned())
                    {
                        Some(match val {
                            Value::Bool(b) => b,
                            _ => bail!("Only expected bool values in bool variables"),
                        })
                    } else {
                        None
                    };
                    let arg = match default {
                        // without default values
                        None => Arg::new(variable.name.clone())
                            .help(help)
                            .long(long)
                            .action(ArgAction::SetTrue),
                        Some(true) => Arg::new(variable.name.clone())
                            .help(help)
                            .long(format!("disable-{long}"))
                            .default_value("true")
                            .action(ArgAction::SetFalse),
                        Some(false) => Arg::new(variable.name.clone())
                            .help(help)
                            .long(format!("enable-{long}"))
                            .action(ArgAction::SetTrue),
                    };
                    cmd = cmd.arg(arg);
                } else {
                    let short = variable.cmdarg.short.to_owned();

                    let default = if let Some(default) = variable
                        .cmdarg
                        .default
                        .to_owned()
                        .or(variable.value.to_owned())
                    {
                        Some(match default {
                            Value::Number(v) => v.to_string(),
                            Value::String(v) => v,
                            _ => bail!(
                            "We only want to see integers or strings in default values for non-bool variables.."
                        ),
                        })
                    } else {
                        None
                    };
                    let arg = Arg::new(variable.name.clone())
                        .action(ArgAction::Set)
                        .help(help)
                        .long(long);
                    let arg = if let Some(s) = short {
                        let chars = s.chars().collect::<Vec<char>>();
                        if chars.len() != 1 {
                            bail!(
                            "Short name for variable `{}` is expected to be just in 1 character",
                            variable.name
                        );
                        }

                        arg.short(chars[0])
                    } else {
                        arg
                    };
                    // For values with defaults, we set the default ones
                    // For other values, if they were not provided when parsing, we'll fill the corresponding memory with zero, or report error, based on what we need
                    let arg = if let Some(default) = default {
                        arg.default_value(default)
                    } else {
                        arg
                    };
                    cmd = cmd.arg(arg);
                }
            }
        }
        Ok(cmd)
    }
}
#[cfg(test)]
mod tests {
    use crate::{meta::EunomiaObjectMeta, tests::get_assets_dir};

    #[test]
    fn test_arg_builder() {
        let skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        for p in cmd.get_arguments() {
            println!("{:?}", p.get_long());
        }
        let cmd = cmd.color(clap::ColorChoice::Never);
        let matches = cmd
            .try_get_matches_from([
                "myprog",
                "--cv1",
                "2333",
                "--const_val_2",
                "12345678",
                "--const_val_3",
                "abcdefg",
                "--bss_val_1",
                "111",
            ])
            .unwrap();
        assert_eq!(
            matches.get_one::<String>("const_val_1"),
            Some(&String::from("2333"))
        );
        assert_eq!(
            matches.get_one::<String>("const_val_2"),
            Some(&String::from("12345678"))
        );
        assert_eq!(
            matches.get_one::<String>("const_val_3"),
            Some(&String::from("abcdefg"))
        );
        assert_eq!(
            matches.get_one::<String>("bss_val_1"),
            Some(&String::from("111"))
        );
        assert_eq!(matches.get_one::<String>("bss_val_2"), None);
        assert_eq!(matches.get_one::<String>("bss_val_3"), None);
    }
    #[test]
    #[should_panic]
    fn test_arg_builder_invalid_argument() {
        let skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        cmd.try_get_matches_from(["prog", "-a", "123"]).unwrap();
    }
    #[test]
    fn test_boolflag() {
        let skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        let matches = cmd
            .clone()
            .try_get_matches_from([
                "prog",
                "--boolflag",
                "--disable-boolflag-with-default-true",
                "--enable-boolflag-with-default-false",
            ])
            .unwrap();
        assert_eq!(matches.get_flag("boolflag"), true);
        assert_eq!(matches.get_flag("boolflag-with-default-true"), false);
        assert_eq!(matches.get_flag("boolflag-with-default-false"), true);

        let matches = cmd.clone().try_get_matches_from(["prog"]).unwrap();
        assert_eq!(matches.get_flag("boolflag"), false);
        assert_eq!(matches.get_flag("boolflag-with-default-true"), true);
        assert_eq!(matches.get_flag("boolflag-with-default-false"), false);
    }
    #[test]
    #[should_panic]
    fn test_boolflag_2() {
        let skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        cmd.clone()
            .try_get_matches_from(["prog", "--enable-boolflag-with-default-true"])
            .unwrap();
    }
    #[test]
    #[should_panic]
    fn test_boolflag_3() {
        let skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        cmd.clone()
            .try_get_matches_from(["prog", "--disable-boolflag-with-default-false"])
            .unwrap();
    }
}
