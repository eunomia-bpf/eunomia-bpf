use std::collections::HashMap;
use std::sync::Weak;
use std::sync::{Arc, Mutex};

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
        let meter = global::meter("ex.com/eunomia");
        let runtime = Builder::new_multi_thread()
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
    pub fn shutdown(self) {
        self.runtime.shutdown_background();
    }
}
