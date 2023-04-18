use crate::Action;
use ecli_lib::error::*;
use ecli_lib::runner::RemoteArgs;
use ecli_lib::Action as ActionFromLib;

impl TryFrom<Action> for RemoteArgs {
    type Error = EcliError;

    fn try_from(act: Action) -> Result<Self, Self::Error> {
        match act {
            Action::Server { .. } => Ok(Self {
                server: Some(act.try_into().unwrap()),
                client: None,
            }),
        }
    }
}

impl TryFrom<Action> for ActionFromLib {
    type Error = EcliError;

    fn try_from(value: Action) -> Result<Self, Self::Error> {
        let Action::Server {
            config,
            secure,
            port,
            addr,
        } = value;

        Ok(ActionFromLib::Server {
            config,
            secure,
            port,
            addr,
        })
    }
}
