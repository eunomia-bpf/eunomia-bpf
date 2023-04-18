//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::Args;
use lib::{runner::RemoteArgs, Action};

impl From<Args> for RemoteArgs {
    fn from(args: Args) -> Self {
        Self {
            server: Some(Action::Server {
                config: args.config,
                port: args.port,
                addr: args.addr,
            }),
            client: None,
        }
    }
}
