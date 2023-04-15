use crate::Action;
use lib::{error::*, runner::RemoteArgs, Action as ActionFromLib};
use std::convert::From;

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

impl From<Action> for ActionFromLib {
    fn from(a: Action) -> Self {
        match a {
            Action::Server {
                config,
                secure,
                port,
                addr,
            } => Self::Server {
                config,
                secure,
                port,
                addr,
            },
        }
    }
}
