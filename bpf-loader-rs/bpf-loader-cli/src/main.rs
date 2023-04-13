use std::thread;

use bpf_loader_lib::{
    clap::{Arg, ArgAction, Command},
    export_event::ExportFormatType,
    meta::{arg_parser::UnpresentVariableAction, ComposedObject, EunomiaObjectMeta},
    skeleton::builder::BpfSkeletonBuilder,
};

use anyhow::{anyhow, bail, Context, Result};
use log::info;
use serde_json::Value;
use signal_hook::{
    consts::{SIGINT, SIGTSTP},
    iterator::Signals,
};
fn main() -> Result<()> {
    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .arg(
            Arg::new("json_skeleton")
                .action(ArgAction::Set)
                .help("The skeleton json file")
                .required(true),
        )
        .arg(
            Arg::new("elf_file")
                .help(
                    "The ELF file; If provided, will use the file \
    here instead of the one from the skeleton",
                )
                .long("elf")
                .short('e')
                .required(false),
        )
        .arg(
            Arg::new("bpf_args")
                .action(ArgAction::Append)
                .help("Args to the bpf program"),
        )
        .arg(
            Arg::new("no-log")
                .long("no-log")
                .help("Disable logs")
                .action(ArgAction::SetTrue),
        )
        .get_matches();
    if !matches.get_flag("no-log") {
        flexi_logger::Logger::try_with_env_or_str("info")?
            .log_to_stdout()
            .start()?;
    }
    let json_skel = matches.get_one::<String>("json_skeleton").unwrap();
    let elf_file = matches.get_one::<String>("elf_file");
    let mut bpf_args = matches
        .get_many::<String>("bpf_args")
        .map(|v| v.map(|s| s.to_owned()).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);
    bpf_args.insert(0, "bpf-prog".into());
    let json_content = serde_json::from_str::<Value>(
        &std::fs::read_to_string(json_skel)
            .with_context(|| anyhow!("Failed to read json skeleton"))?,
    )
    .with_context(|| anyhow!("Failed to parse json"))?;
    let (prog_bin, mut meta) = if let Some(elf_file) = elf_file {
        let elf_bin =
            std::fs::read(elf_file).with_context(|| anyhow!("Failed to read elf file"))?;
        let meta = match serde_json::from_value::<ComposedObject>(json_content.clone()) {
            Err(e) => {
                info!(
                    "Failed to parse json skeleton into ComposedObject, trying meta.. {}",
                    e
                );
                match serde_json::from_value::<EunomiaObjectMeta>(json_content) {
                        Err(e) =>       bail!("Failed to parse json skeleton into ComposedObject and EunomiaObjectMeta: {}",e),
                        Ok(v) => v
                    }
            }
            Ok(v) => v.meta,
        };
        (elf_bin, meta)
    } else {
        let data = serde_json::from_value::<ComposedObject>(json_content)
            .with_context(|| anyhow!("Failed to parse json into ComposedObject"))?;
        (data.bpf_object, data.meta)
    };

    let bpf_parser = meta.build_argument_parser()?;
    let bpf_matches = bpf_parser.get_matches_from(bpf_args);
    meta.parse_arguments_and_fill_skeleton_variables(
        &bpf_matches,
        UnpresentVariableAction::FillWithZero,
    )?;

    let skel = BpfSkeletonBuilder::from_object_meta_and_object_buffer(&meta, &prog_bin, None)
        .build()
        .with_context(|| anyhow!("Failed to build PreLoadSkeleton"))?
        .load_and_attach()
        .with_context(|| anyhow!("Failed to load or attach the bpf skeleton"))?;
    let handle = skel.create_poll_handle();
    let mut signals = Signals::new([SIGINT, SIGTSTP])?;
    thread::spawn(move || {
        let mut paused = false;
        for sig in signals.forever() {
            match sig {
                SIGINT => {
                    info!("Terminating the poller..");
                    handle.set_pause(false);
                    handle.terminate();
                    break;
                }
                SIGTSTP => {
                    if paused {
                        info!("Continuing..");
                        handle.set_pause(false);
                        paused = false;
                    } else {
                        info!("Send SIGTSTP again to resume (Ctrl + Z)");
                        handle.set_pause(true);
                        paused = true;
                    }
                }

                _ => continue,
            }
        }
    });
    skel.wait_and_poll_to_handler(ExportFormatType::PlainText, None, None)
        .with_context(|| anyhow!("Failed to poll"))?;
    Ok(())
}
