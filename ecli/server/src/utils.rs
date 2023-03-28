use crate::Args;
use lib::{error::*, runner::RemoteArgs, Action};

impl TryFrom<Args> for RemoteArgs {
    type Error = EcliError;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        match args {
            Args { .. } => Ok(Self {
                server: Some(Action::Server {
                    config: args.config,
                    secure: args.secure,
                    port: args.port,
                    addr: args.addr,
                }),
                client: None,
            }),
        }
    }
}
