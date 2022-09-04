use std::collections::HashMap;
use std::sync::Weak;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use opentelemetry::{global, metrics::Counter, KeyValue};

use opentelemetry::sdk::Resource;
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::proto::MetricFamily;
use tokio::runtime::{Builder, Runtime};

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
        print!("{} ", event.messgae);
        self.http_counter
            .add(1, &[KeyValue::new("key", event.messgae.to_string())]);
    }
}

pub struct BPFProgramManager<'a> {
    states: Mutex<HashMap<u32, Arc<BPFProgramState<'a>>>>,
    id: u32,
}

impl<'a> BPFProgramManager<'a> {
    pub fn new() -> BPFProgramManager<'a> {
        BPFProgramManager {
            states: Mutex::new(HashMap::new()),
            id: 0,
        }
    }
    pub fn add_ebpf_prog(&mut self, prog: Arc<BPFProgramState<'a>>) {
        let mut progs = self.states.lock().unwrap();
        progs.insert(self.id, prog);
        self.id += 1;
    }
    pub async fn run_ebpf(
        &mut self,
        json_data: &'a str,
        name: String,
        cb: Weak<impl HandleBPFEvent + 'a>,
    ) -> Result<()> {
        // let future = tokio::spawn(async move {
        //     let mut prog = BPFProgramState::new(json_data, name)?;
        //     prog.run(cb)?;
        //     prog.wait_and_export()
        // });
        Ok(())
    }
    pub fn list_all_progs(&self) -> Vec<(u32, String)> {
        let progs = self.states.lock().unwrap();
        let mut result = Vec::new();
        for (id, prog) in progs.iter() {
            result.push((*id, prog.name.clone()));
        }
        result
    }
}

pub struct BPFProgramState<'a> {
    name: String,
    program: BPFProgram<'a>,
}

impl<'a> BPFProgramState<'a> {
    pub fn new(json_data: String, name: String) -> Result<BPFProgramState<'a>> {
        let program = BPFProgram::create_ebpf_program(json_data)?;
        Ok(BPFProgramState { name, program })
    }
    pub fn run(&mut self, cb: Weak<impl HandleBPFEvent + 'a>) -> Result<()> {
        self.program.run()?;
        self.program.register_handler(cb);
        Ok(())
    }
    pub fn wait_and_export(&self) -> Result<()> {
        self.program.wait_and_export()?;
        Ok(())
    }
    pub fn stop(&self) {
        self.program.stop();
    }
}
