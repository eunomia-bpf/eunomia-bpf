//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::time::Duration;

use clap::ArgAction;
use clap::Parser;
use ecli_lib::config::ProgramType;
use ecli_lib::{
    runner::{
        client::{http::EcliHttpClient, AbstractClient},
        ProgramHandle,
    },
};

use crate::helper::load_prog_buf_and_guess_type;
#[derive(Parser)]
pub struct ClientCmd {
    #[clap(subcommand)]
    pub cmd: ClientSubCommand,

    #[clap(flatten)]
    pub opts: ClientOpts,
}

#[derive(Parser)]
pub enum ClientSubCommand {
    #[clap(
        name = "start",
        about = "Start an ebpf program on the specified endpoint"
    )]
    Start(StartCommand),

    #[clap(name = "stop", about = "Stop running a task on the specified endpoint")]
    Stop(StopCommand),

    #[clap(name = "log", about = "Fetch logs of the given task")]
    Log(LogCommand),

    #[clap(name = "pause", about = "Pause the task")]
    Pause(PauseCommand),

    #[clap(name = "resume", about = "Resume the task")]
    Resume(ResumeCommand),
    #[clap(name = "list", about = "List tasks on the server")]
    List,
}

#[derive(Parser)]
pub struct ClientOpts {
    #[clap(
        short,
        long,
        help = "API endpoint",
        default_value = "http://127.0.0.1:8527"
    )]
    pub endpoint: String,
}

#[derive(Parser)]
pub struct StartCommand {
    #[clap(
        required = true,
        help = "ebpf program URL or local path, set it `-` to read the program from stdin"
    )]
    pub prog: String,
    #[clap(long, short)]
    pub name: Option<String>,
    #[clap(long, short = 'j', help = "Use json as output format")]
    pub export_json: bool,
    #[clap(action = ArgAction::Append, help = "Extra args to the program")]
    pub extra_args: Vec<String>,
    #[clap(long, short, help = "Manually specity the program type", value_parser = crate::helper::prog_type_value_parser)]
    pub prog_type: Option<ProgramType>,
}

#[derive(Parser)]
pub struct LogCommand {
    #[clap(required = true, help = "ID of the task")]
    pub id: ProgramHandle,
    #[clap(
        short,
        long,
        help = "Keeping tracking logs of the task until exited",
        default_value = "false"
    )]
    pub follow: bool,
    #[clap(short, long, help = "only fetch logs with cursor >= this")]
    pub cursor: Option<usize>,
}

#[derive(Parser)]
pub struct StopCommand {
    #[clap(required = true, help = "ID of the task")]
    pub id: ProgramHandle,
}

#[derive(Parser)]
pub struct PauseCommand {
    #[clap(required = true, help = "ID of the task")]
    pub id: ProgramHandle,
}

#[derive(Parser)]
pub struct ResumeCommand {
    #[clap(required = true, help = "ID of the Task")]
    pub id: ProgramHandle,
}

pub(crate) async fn handle_client_command(cmd: ClientCmd) -> anyhow::Result<()> {
    let client = EcliHttpClient::new(cmd.opts.endpoint)?;
    match cmd.cmd {
        ClientSubCommand::Start(StartCommand {
            prog,
            extra_args,
            name,
            export_json,
            prog_type: user_prog_type,
        }) => {
            let (buf, prog_type) = load_prog_buf_and_guess_type(&prog, user_prog_type).await?;

            let handle = client
                .start_program(name, &buf, prog_type, export_json, &extra_args, None)
                .await?;
            println!("{}", handle);
        }
        ClientSubCommand::Stop(StopCommand { id }) => {
            client.terminate_program(id).await?;
        }

        ClientSubCommand::Pause(PauseCommand { id }) => {
            client.set_program_pause_state(id, true).await?;
        }
        ClientSubCommand::Resume(ResumeCommand { id }) => {
            client.set_program_pause_state(id, false).await?;
        }
        ClientSubCommand::List => {
            for item in client.get_program_list().await? {
                println!("{} {} {:?}", item.id, item.name, item.status);
            }
        }
        ClientSubCommand::Log(LogCommand { id, follow, cursor }) => {
            if follow {
                let mut last_poll = None;
                loop {
                    let logs = client.fetch_logs(id, last_poll, None).await?;
                    for (cursor, log) in logs.into_iter() {
                        println!("{}", log.log);
                        last_poll = Some(cursor + 1);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } else {
                let logs = client.fetch_logs(id, cursor, None).await?;
                let mut last_cursor = None;
                for (cursor, log) in logs.into_iter() {
                    last_cursor = Some(cursor);
                    match log.log_type {
                        ecli_lib::runner::LogType::Stdout => {
                            print!("{}", log.log);
                        }
                        ecli_lib::runner::LogType::Stderr => {
                            eprint!("{}", log.log);
                        }
                        ecli_lib::runner::LogType::Plain => {
                            println!("<{}> {}", log.timestamp, log.log);
                        }
                    }
                }
                if let Some(v) = last_cursor {
                    println!();
                    println!("Next cursor: {}", v);
                } else {
                    println!("No logs fetched");
                }
            }
        }
    };
    Ok(())
}
