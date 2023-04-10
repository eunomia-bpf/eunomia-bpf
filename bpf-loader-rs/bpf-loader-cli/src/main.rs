use std::thread;

use bpf_loader_lib::{
    export_event::ExportFormatType,
    meta::{ComposedObject, EunomiaObjectMeta},
    skeleton::builder::BpfSkeletonBuilder,
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(help = "The skeleton json file")]
    json_skeleton: String,
    #[arg(
        help = "The ELF file; If provided, will use the file here instead of the one from the skeleton"
    )]
    elf_file: Option<String>,
}

use anyhow::{anyhow, bail, Context, Result};
use log::info;
use serde_json::Value;
use signal_hook::{consts::SIGINT, iterator::Signals};
fn main() -> Result<()> {
    flexi_logger::Logger::try_with_env_or_str("info")?
        .log_to_stdout()
        .start()?;
    let args = Args::parse();
    let json_content = serde_json::from_str::<Value>(
        &std::fs::read_to_string(&args.json_skeleton)
            .with_context(|| anyhow!("Failed to read json skeleton"))?,
    )
    .with_context(|| anyhow!("Failed to parse json"))?;
    let (prog_bin, meta) = if let Some(elf_file) = &args.elf_file {
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
    let skel = BpfSkeletonBuilder::from_object_meta_and_object_buffer(&meta, &prog_bin, None)
        .build()
        .with_context(|| anyhow!("Failed to build PreLoadSkeleton"))?
        .load_and_attach()
        .with_context(|| anyhow!("Failed to load or attach the bpf skeleton"))?;
    let handle = skel.create_poll_handle();
    let mut signals = Signals::new([SIGINT])?;
    thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGINT {
                info!("Terminating the poller..");
                handle.terminate();
                break;
            }
        }
    });
    skel.wait_and_poll_to_handler(ExportFormatType::PlainText, None, None)
        .with_context(|| anyhow!("Failed to poll"))?;
    Ok(())
}
