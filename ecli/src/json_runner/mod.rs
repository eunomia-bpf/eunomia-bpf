//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::sync::Arc;
use std::thread::JoinHandle;

use bpf_loader_lib::export_event::EventHandler;
use bpf_loader_lib::export_event::ReceivedEventData;
use bpf_loader_lib::meta::arg_parser::UnpresentVariableAction;
use bpf_loader_lib::meta::ComposedObject;
use bpf_loader_lib::skeleton::builder::BpfSkeletonBuilder;
use bpf_loader_lib::skeleton::handle::PollingHandle;

use crate::config::ProgramConfigData;
use crate::error::EcliError;
use crate::error::EcliResult;

struct EcliEventHandler;

impl EventHandler for EcliEventHandler {
    fn handle_event(
        &self,
        _context: Option<std::sync::Arc<dyn std::any::Any>>,
        data: bpf_loader_lib::export_event::ReceivedEventData,
    ) {
        match data {
            ReceivedEventData::PlainText(s) | ReceivedEventData::JsonText(s) => println!("{}", s),
            _ => unreachable!(),
        }
    }
}
/// Run a config-defined ebpf program async
/// The config has the same meaning as the sync version
/// But this function won't wait until the program exited, it will return once the arg parsing is done.
/// It returns a tuple, the first element is a PollingHandle used to control the poll process. It can pause, resume or terminate the polling function
/// It will be Some(T) if the polling function was started successfully
/// The second element is a JoinHandle which can be used to wait until the polling function returns.
pub fn handle_json_async(
    conf: ProgramConfigData,
) -> EcliResult<(Option<PollingHandle>, JoinHandle<EcliResult<()>>)> {
    let mut package = serde_json::from_str::<ComposedObject>(
        &String::from_utf8(conf.program_data_buf.clone()).map_err(|e| {
            EcliError::Other(format!("Failed to deserialize json string to utf8: {}", e))
        })?,
    )
    .map_err(|e| {
        EcliError::BpfError(format!(
            "Failed to deserialize `ComposedObject` from input string: {}",
            e
        ))
    })?;
    let parser = package.meta.build_argument_parser().map_err(|e| {
        EcliError::Other(format!(
            "Failed to build argument parser from skeleton: {}",
            e
        ))
    })?;
    let mut args = vec![conf.url.clone()];
    args.extend(conf.extra_arg.iter().map(String::to_owned));
    let matches = parser.get_matches_from(args.into_iter());
    package
        .meta
        .parse_arguments_and_fill_skeleton_variables(
            &matches,
            UnpresentVariableAction::FillWithZero,
        )
        .map_err(|e| EcliError::Other(format!("Failed to parse args: {}", e)))?;
    let (tx, rx) = std::sync::mpsc::channel::<PollingHandle>();

    let join_handle = std::thread::spawn(move || {
        let skel = BpfSkeletonBuilder::from_json_package(&package, conf.btf_path.as_deref())
            .build()
            .map_err(|e| EcliError::BpfError(format!("Failed to build preload seleton: {}", e)))?;
        let skel = skel.load_and_attach().map_err(|e| {
            EcliError::BpfError(format!("Failed to load or attach bpf program: {}", e))
        })?;
        tx.send(skel.create_poll_handle())
            .map_err(|e| EcliError::Other(e.to_string()))?;
        skel.wait_and_poll_to_handler(
            conf.export_format_type,
            Some(Arc::new(EcliEventHandler)),
            None,
        )
        .map_err(|e| EcliError::BpfError(format!("Failed to poll: {}", e)))?;
        EcliResult::Ok(())
    });

    Ok((rx.recv().ok(), join_handle))
}

/// Takes a ProgramConfigData as input and executes an eBPF program using the configuration data provided.
/// The function converts the JSON data into a CString and creates a vector of arguments to pass to the eBPF program.
/// The eBPF program is then loaded and attached, and events are polled and handled using the specified handler function.
pub fn handle_json(conf: ProgramConfigData) -> EcliResult<()> {
    let (_, join_handle) = handle_json_async(conf)?;
    join_handle
        .join()
        .map_err(|_| EcliError::Other("Failed to join".to_string()))?
}
