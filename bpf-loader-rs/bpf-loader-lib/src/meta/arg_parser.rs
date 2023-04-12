use anyhow::{anyhow, bail, Context, Result};
use clap::ArgMatches;
use serde_json::{json, Value};

use super::EunomiaObjectMeta;

/// What to do if we met a variable which neither has the default value or has been supplied from command argument
pub enum UnpresentVariableAction {
    FillWithZero,
    ReportError,
}

impl EunomiaObjectMeta {
    pub fn parse_arguments_and_fill_skeleton_variables(
        &mut self,
        args: &ArgMatches,
        on_unpresent: UnpresentVariableAction,
    ) -> Result<()> {
        for section in self.bpf_skel.data_sections.iter_mut() {
            for variable in section.variables.iter_mut() {
                if variable.name.starts_with("__eunomia_dummy") {
                    continue;
                }
                if variable.ty == "bool" {
                    let flag = args.get_one::<bool>(&variable.name).unwrap();
                    variable.value = Some(json!(flag));
                } else {
                    let user_value = args
                        .get_one::<String>(&variable.name)
                        .map(|v| v.to_string());
                    let parsed_value = if let Some(user_value) = user_value {
                        parse_value(&variable.ty, user_value).with_context(|| {
                            anyhow!("Failed to parse user input value of `{}`", variable.name)
                        })?
                    } else {
                        match on_unpresent {
                            UnpresentVariableAction::FillWithZero => {
                                make_zero_filled_value(&variable.ty)?
                            }
                            UnpresentVariableAction::ReportError => bail!(
                                "Variable `{}` has neither default values nor command-line sources",
                                variable.name
                            ),
                        }
                    };
                    variable.value = Some(parsed_value);
                }
            }
        }
        self.debug_verbose = args.get_flag("verbose");
        Ok(())
    }
}

macro_rules! parse_value_decl {
    ($raw_value: expr, $input_ty_name: expr,  $(($type_name: expr, $to_type: ty)), * ) => {
        {
            use anyhow::{anyhow,  Context};
            use serde_json::json;
            match $input_ty_name {
                $(
                    $type_name => Some(json!(
                        $raw_value.parse::<$to_type>().with_context(|| anyhow!("Failed to parse `{}` into {}", $raw_value, stringify!($to_type)))?
                    )),
                )*
                _ => None
            }
        }
    };
}

fn parse_value(ty: &str, v: impl AsRef<str>) -> Result<Value> {
    let s = v.as_ref();
    let result = parse_value_decl!(
        s,
        ty,
        ("bool", bool),
        ("pid_t", i32),
        ("int", i32),
        ("short", i16),
        ("long", i64),
        ("long long", i64),
        ("unsigned int", u32),
        ("unsigned short", u16),
        ("unsigned long long", u64),
        ("float", f32),
        ("double", f64)
    );
    if let Some(v) = result {
        Ok(v)
    } else if ty.starts_with("char[") {
        Ok(json!(s))
    } else {
        bail!("Not supporting parsing into type `{}`", ty);
    }
}
fn make_zero_filled_value(ty: &str) -> Result<Value> {
    let result = match ty {
        "bool" => json!(false),
        "pid_t" | "int" | "short" | "long" | "long long" | "unsigned int" | "unsigned short"
        | "unsigned long long" => json!(0),
        "float" | "double" => json!(0.0),
        s if s.starts_with("char[") => json!(""),
        s => bail!("Unable to make zero-filled data for type {}", s),
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        meta::{arg_parser::UnpresentVariableAction, EunomiaObjectMeta},
        tests::get_assets_dir,
    };

    #[test]
    fn test_arg_parser() {
        let mut skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        let matches = cmd
            .try_get_matches_from([
                "myprog",
                "-1",
                "1234",
                "--const_val_2",
                "2345",
                "--const_val_3",
                "abcdefg",
                "--boolflag",
                "--bss_val_1",
                "7890",
            ])
            .unwrap();
        skel.parse_arguments_and_fill_skeleton_variables(
            &matches,
            UnpresentVariableAction::FillWithZero,
        )
        .unwrap();
        println!("{:#?}", skel.bpf_skel.data_sections);
        let sections = &skel.bpf_skel.data_sections;
        assert_eq!(sections[0].variables[0].value, Some(json!(1234)));
        assert_eq!(sections[0].variables[1].value, Some(json!(2345)));
        assert_eq!(sections[0].variables[2].value, Some(json!("abcdefg")));
        assert_eq!(sections[0].variables[3].value, Some(json!(true)));
        assert_eq!(sections[1].variables[0].value, Some(json!(7890)));
    }
    #[test]
    #[should_panic = "Failed to parse `abcdefg` into i32"]
    fn test_arg_parser_with_invalid_value_1() {
        let mut skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        let matches = cmd
            .try_get_matches_from(["myprog", "-1", "abcdefg"])
            .unwrap();
        skel.parse_arguments_and_fill_skeleton_variables(
            &matches,
            UnpresentVariableAction::FillWithZero,
        )
        .unwrap();
    }
    #[test]
    #[should_panic = "Failed to parse `111111111111111111` into i32"]
    fn test_arg_parser_with_invalid_value_2() {
        let mut skel = serde_json::from_str::<EunomiaObjectMeta>(
            &std::fs::read_to_string(get_assets_dir().join("arg_builder_test").join("skel.json"))
                .unwrap(),
        )
        .unwrap();
        let cmd = skel.build_argument_parser().unwrap();
        let matches = cmd
            .try_get_matches_from(["myprog", "-1", "111111111111111111"])
            .unwrap();
        skel.parse_arguments_and_fill_skeleton_variables(
            &matches,
            UnpresentVariableAction::FillWithZero,
        )
        .unwrap();
    }
}
