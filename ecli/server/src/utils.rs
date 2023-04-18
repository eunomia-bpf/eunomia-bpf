//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::Action;
use crate::Args;
use lib::{error::*, runner::RemoteArgs, Action as ActionFromLib};
use lib::{runner::RemoteArgs, Action};
use std::convert::From;

impl From<Args> for RemoteArgs {
    fn from(args: Args) -> Self {
        Self {
            server: Some(Action::Server {
                config: args.config,
                secure: false,
                port: args.port,
                addr: args.addr,
            }),
            client: None,
        }
    }
}
