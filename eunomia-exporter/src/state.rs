use std::collections::HashMap;
use std::sync::Weak;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use opentelemetry::{global, metrics::Counter, KeyValue};

use opentelemetry::sdk::Resource;
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::proto::MetricFamily;
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

use crate::bindings::{BPFEvent, BPFProgram, HandleBPFEvent};
use crate::config::ExporterConfig;

pub struct AppState {
    runtime: Runtime,
    exporter: PrometheusExporter,
    http_counter: Counter<u64>,
}

fn init_meter() -> PrometheusExporter {
    opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new(
            "R",
            String::from("Rust"),
        )]))
        .init()
}

impl AppState {
    pub fn init(config: &ExporterConfig) -> AppState {
        let exporter = init_meter();
        let meter = global::meter("ex.com/hyper");
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let state = AppState {
            runtime,
            exporter,
            http_counter: meter
                .u64_counter("example.http_requests_total")
                .with_description("Total number of HTTP requests made.")
                .init(),
        };
        state
    }
    pub fn gather(&self) -> Vec<MetricFamily> {
        self.exporter.registry().gather()
    }
    pub fn get_runtime(&self) -> &Runtime {
        return &self.runtime;
    }
}

impl<'a> HandleBPFEvent for AppState {
    fn on_event(&self, event: &BPFEvent) {
        println!("{}", event.messgae);
        self.http_counter
            .add(1, &[KeyValue::new("key", event.messgae.to_string())]);
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
    handler: JoinHandle<Result<()>>,
}

impl<'a> BPFProgramState<'a> {
    pub fn run_and_wait(
        json_data: String,
        name: String,
        cb: Weak<AppState>,
        runtime: &Runtime,
    ) -> Result<BPFProgramState<'a>> {
        let mut program = BPFProgram::create_ebpf_program(json_data)?;
        program.register_handler(cb);
        let program = Arc::new(program);
        let new_prog = program.clone();
        let handler = runtime.spawn(async move {
            new_prog.run()?;
            print!("Running ebpf program");
            new_prog.wait_and_export()
        });
        let state = BPFProgramState {
            name,
            program,
            handler,
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
    use crate::config;
    use std::{fs, time::Duration, time::Instant};

    #[test]
    fn test_async_start_ebpf_program_state() {
        let config = config::ExporterConfig {};
        let state = Arc::new(AppState::init(&config));

        let json_data = fs::read_to_string("tests/package.json").unwrap();
        let now = Instant::now();
        let ebpf_program = BPFProgramState::run_and_wait(
            json_data,
            "hello".to_string(),
            Arc::downgrade(&state),
            state.get_runtime(),
        )
        .unwrap();
        let elapsed_time = now.elapsed();
        println!(
            "Running slow_function() took {} ms.",
            elapsed_time.as_millis()
        );
        std::thread::sleep(Duration::from_secs(5));
        println!("Finished time-consuming task.");
        ebpf_program.stop();
    }
}
