use anyhow::Result;
use opentelemetry::{global, metrics::Counter, KeyValue};
use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{Arc, Weak},
};
use tokio::task::JoinHandle;

use crate::{
    bindings::{BPFEvent, BPFProgram, HandleBPFEvent},
    config::{CounterConfig, MetricsConfig, ProgramConfig},
    state::AppState,
};

struct BPFEventHandler<'a> {
    http_counter: Counter<u64>,
    marker: PhantomData<&'a ()>,
}

impl<'a> HandleBPFEvent for BPFEventHandler<'a> {
    fn on_event(&self, event: &BPFEvent) {
        // println!("{}", event.messgae);
        self.http_counter
            .add(1, &[KeyValue::new("key", event.messgae.to_string())]);
    }
}

impl<'a> BPFEventHandler<'a> {
    pub fn new(config: MetricsConfig) -> Result<BPFEventHandler<'a>> {
        let meter = global::meter("ex.com/eunomia");
        let http_counter = meter
            .u64_counter("example.http_requests_total")
            .with_description("Total number of HTTP requests made.")
            .try_init()?;
        Ok(BPFEventHandler {
            http_counter,
            marker: PhantomData,
        })
    }
}

pub struct BPFProgramManager<'a> {
    states: HashMap<u32, BPFProgramState<'a>>,
    id: u32,
}

impl<'a> BPFProgramManager<'a> {
    pub fn new() -> BPFProgramManager<'a> {
        BPFProgramManager {
            states: HashMap::new(),
            id: 0,
        }
    }
    pub fn add_bpf_prog(&mut self, prog: BPFProgramState<'a>) {
        self.states.insert(self.id, prog);
        self.id += 1;
    }
    pub fn list_all_progs(&self) -> Vec<(u32, String)> {
        let mut result = Vec::new();
        for (id, prog) in self.states.iter() {
            result.push((*id, prog.name.clone()));
        }
        result
    }
    pub fn remove_bpf_prog(&mut self, id: u32) -> Result<()> {
        self.states.remove(&id);
        Ok(())
    }
}

pub struct BPFProgramState<'a> {
    name: String,
    program: Arc<BPFProgram<'a>>,
    event_handler: Arc<BPFEventHandler<'a>>,
    join_handler: JoinHandle<Result<()>>,
}

impl<'a> BPFProgramState<'a> {
    pub fn run_and_wait(
        config: ProgramConfig,
        state: Arc<AppState>,
    ) -> Result<BPFProgramState<'a>> {
        let mut program = BPFProgram::create_ebpf_program(config.ebpf_data)?;
        let event_handler = Arc::new(BPFEventHandler::new(config.metrics)?);
        program.register_handler(Arc::downgrade(&event_handler));

        let program = Arc::new(program);
        let new_prog = program.clone();
        let handler = state.get_runtime().spawn(async move {
            new_prog.run()?;
            print!("Running ebpf program");
            new_prog.wait_and_export()
        });
        println!("Running ebpf program {}", config.name);
        let state = BPFProgramState {
            name: config.name,
            program,
            event_handler,
            join_handler: handler,
        };
        Ok(state)
    }
    pub fn stop(&self) {
        self.program.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExporterConfig;
    use std::{fs, time::Duration, time::Instant, process::exit};

    #[test]
    #[ignore]
    fn test_async_start_ebpf_program_state() {
        let config = ExporterConfig::default();
        let state = Arc::new(AppState::init(&config));
        let new_state = state.clone();
        new_state.get_runtime().spawn(async move {
            let json_data = fs::read_to_string("tests/package.json").unwrap();
            let mut prog_config = ProgramConfig::default();
            prog_config.ebpf_data = json_data;
            let now = Instant::now();
            let ebpf_program = BPFProgramState::run_and_wait(prog_config, state).unwrap();
            let elapsed_time = now.elapsed();
            println!(
                "Running slow_function() took {} ms.",
                elapsed_time.as_millis()
            );
            ebpf_program.stop();
        });
        std::thread::sleep(Duration::from_secs(5));
        println!("Finished time-consuming task.");
    }
}
