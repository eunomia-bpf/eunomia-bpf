use crate::Args;
use lib::{error::*, runner::RemoteArgs, Action};

impl From<Args> for RemoteArgs {
    fn from(args: Args) -> Self {
        Self {
            server: Some(Action::Server {
                config: args.config,
                secure: args.secure,
                port: args.port,
                addr: args.addr,
            }),
            client: None,
        }
    }
}
