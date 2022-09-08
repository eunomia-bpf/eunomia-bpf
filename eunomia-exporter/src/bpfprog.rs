use anyhow::Result;
use opentelemetry::{global, metrics::Counter, KeyValue};
use serde_json::Value;
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use tokio::task::JoinHandle;

use crate::{
    bindings::{BPFEvent, BPFProgram, HandleBPFEvent},
    config::{ExporterConfig, MetricsConfig, ProgramConfig},
    state::AppState,
};

struct BPFEventHandler<'a> {
    counters: Vec<Counter<u64>>,
    config: MetricsConfig,
    marker: PhantomData<&'a ()>,
}

impl<'a> HandleBPFEvent for BPFEventHandler<'a> {
    fn on_event(&self, event: &BPFEvent) {
        let v = serde_json::from_str(event.messgae);
        if v.is_err() {
            return;
        }
        let v: Value = v.unwrap();
        let len = self.counters.len();

        for i in 0..len {
            let config = &self.config.counters[i];
            let counter = &self.counters[i];
            let mut labels = Vec::new();
            for label in &config.labels {
                let key = if label.from.len() == 0 {
                    &label.name
                } else {
                    &label.from
                };
                let value = v.get(key);
                if value.is_none() {
                    continue;
                }
                labels.push(KeyValue::new(
                    label.name.clone(),
                    value.unwrap().to_string(),
                ));
            }
            counter.add(1, &labels);
        }
    }
}

impl<'a> BPFEventHandler<'a> {
    pub fn new(config: MetricsConfig) -> Result<BPFEventHandler<'a>> {
        let meter = global::meter("ex.com/eunomia");
        let mut counters = Vec::new();
        for counter in &config.counters {
            let counter = meter
                .u64_counter(counter.name.clone())
                .with_description(counter.description.clone())
                .init();
            counters.push(counter);
        }
        Ok(BPFEventHandler {
            counters,
            config,
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
    fn insert_bpf_prog(&mut self, prog: BPFProgramState<'a>) -> u32 {
        self.states.insert(self.id, prog);
        let id = self.id;
        self.id += 1;
        id
    }
    pub fn list_all_progs(&self) -> Vec<(u32, String)> {
        let mut result = Vec::new();
        for (id, prog) in self.states.iter() {
            result.push((*id, prog.name.clone()));
        }
        result
    }
    pub fn remove_bpf_prog(&mut self, id: u32) -> Result<()> {
        if let Some(prog) = self.states.remove(&id) {
            prog.stop();
        }
        self.states.remove(&id);
        Ok(())
    }
    pub fn add_bpf_prog(&mut self, config: &ProgramConfig, state: Arc<AppState>) -> Result<u32> {
        let prog = BPFProgramState::run_and_wait(config, state)?;
        Ok(self.insert_bpf_prog(prog))
    }
    pub fn start_programs_for_exporter(
        &mut self,
        config: &ExporterConfig,
        state: Arc<AppState>,
    ) -> Result<()> {
        for program in &config.programs {
            self.add_bpf_prog(program, state.clone())?;
        }
        Ok(())
    }
}

pub struct BPFProgramState<'a> {
    name: String,
    program: Arc<BPFProgram<'a>>,
    _event_handler: Arc<BPFEventHandler<'a>>,
    _join_handler: JoinHandle<Result<()>>,
}

impl<'a> BPFProgramState<'a> {
    pub fn run_and_wait(
        config: &ProgramConfig,
        state: Arc<AppState>,
    ) -> Result<BPFProgramState<'a>> {
        let mut program = BPFProgram::create_ebpf_program(config.ebpf_data.clone())?;
        let event_handler = Arc::new(BPFEventHandler::new(config.metrics.clone())?);
        program.register_handler(Arc::downgrade(&event_handler));

        let program = Arc::new(program);
        let start_time = std::time::Instant::now();
        program.run()?;
        let new_prog = program.clone();
        let handler = state.get_runtime().spawn_blocking(move || {
            new_prog.wait_and_export()
        });
        let duration = start_time.elapsed();
        println!("Running ebpf program {} takes {} ms", config.name, duration.as_millis());
        let state = BPFProgramState {
            name: config.name.clone(),
            program,
            _event_handler: event_handler,
            _join_handler: handler,
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
    use std::{fs, time::Duration, time::Instant};

    #[test]
    #[ignore]
    fn test_async_ebpf_program_state() {
        let _config = ExporterConfig::default();
        let state = Arc::new(AppState::init());
        let new_state = state.clone();
        new_state.get_runtime().spawn(async move {
            let json_data = fs::read_to_string("tests/package.json").unwrap();
            let mut prog_config = ProgramConfig::default();
            prog_config.ebpf_data = json_data;
            let now = Instant::now();
            let ebpf_program = BPFProgramState::run_and_wait(&prog_config, state).unwrap();
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
