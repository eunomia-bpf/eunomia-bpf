use opentelemetry::{global, metrics::Counter, Context, KeyValue};

use opentelemetry::sdk::Resource;
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::proto::MetricFamily;

use crate::bindings::{BPFEvent, HandleBPFEvent};
use crate::config::ExporterConfig;

pub struct AppState {
    exporter: PrometheusExporter,
    http_counter: Counter<u64>,
}

fn init_meter() -> PrometheusExporter {
    opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("R", "V")]))
        .init()
}

impl AppState {
    pub fn init(config: &ExporterConfig) -> AppState {
        let exporter = init_meter();
        let meter = global::meter("ex.com/hyper");
        let state = AppState {
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
}

impl HandleBPFEvent for AppState {
    fn on_event(&self, event: &BPFEvent) {
        let cx = Context::new();
        self.http_counter.add(1, &[KeyValue::new("key", "value")]);
    }
}
