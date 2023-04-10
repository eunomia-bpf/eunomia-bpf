use crate::Action;
use lib::{
    self,
    config::ProgramType,
    error::*,
    oci::{PullArgs, PushArgs},
    runner::{ClientActions, ClientArgs, ClientSubCommand, RemoteArgs, RunArgs},
};

impl TryFrom<Action> for RunArgs {
    type Error = EcliError;

    fn try_from(act: Action) -> Result<Self, Self::Error> {
        let Action::Run { no_cache, json, mut prog } = act else {
            unreachable!()
        };
        if prog.len() == 0 {
            return Err(EcliError::ParamErr("prog not present".to_string()));
        }
        Ok(Self {
            no_cache,
            export_to_json: json,
            file: prog.remove(0),
            extra_arg: prog,
            prog_type: ProgramType::Undefine,
        })
    }
}

impl TryFrom<Action> for RemoteArgs {
    type Error = EcliError;

    fn try_from(act: Action) -> Result<Self, Self::Error> {
        match act {
            Action::Client(..) => Ok(Self {
                client: Some(act.try_into().unwrap()),
                server: None,
            }),
            _ => unreachable!(),
        }
    }
}

impl TryFrom<Action> for ClientArgs {
    type Error = EcliError;

    fn try_from(act: Action) -> Result<Self, Self::Error> {
        if let Action::Client(c) = act {
            // deconstruct ClientCmd
            match c.cmd {
                ClientSubCommand::Start(mut start_cmd) => Ok(Self {
                    action_type: ClientActions::Start,
                    endpoint: c.opts.endpoint,
                    port: c.opts.port,
                    run_args: RunArgs {
                        file: start_cmd.prog.remove(0),
                        extra_arg: start_cmd.prog,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ClientSubCommand::Stop(cmd) => Ok(Self {
                    action_type: ClientActions::Stop,
                    id: cmd.id,
                    endpoint: c.opts.endpoint,
                    port: c.opts.port,
                    ..Default::default()
                }),
                ClientSubCommand::List => Ok(Self {
                    endpoint: c.opts.endpoint,
                    port: c.opts.port,
                    ..Default::default()
                }),
                ClientSubCommand::Log(cmd) => Ok(Self {
                    action_type: ClientActions::Log,
                    id: cmd.id,
                    endpoint: c.opts.endpoint,
                    port: c.opts.port,
                    ..Default::default()
                }),
                // ClientSubCommand::Pause(cmd) => Ok(Self {
                //     action_type: ClientActions::Pause,
                //     id: cmd.id,
                //     endpoint: c.opts.endpoint,
                //     port: c.opts.port,
                //     ..Default::default()
                // }),
                // ClientSubCommand::Resume(cmd) => Ok(Self {
                //     action_type: ClientActions::Resume,
                //     id: cmd.id,
                //     endpoint: c.opts.endpoint,
                //     port: c.opts.port,
                //     ..Default::default()
                // }),
            }
        } else {
            unreachable!()
        }
    }
}

impl TryFrom<Action> for PushArgs {
    type Error = EcliError;

    fn try_from(value: Action) -> Result<Self, Self::Error> {
        let Action::Push { module, image } = value else {
            unreachable!()
        };

        Ok(PushArgs {
            file: module,
            image_url: image,
        })
    }
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
