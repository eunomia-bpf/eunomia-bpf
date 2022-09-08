use opentelemetry_prometheus::PrometheusExporter;
use prometheus::proto::MetricFamily;
use tokio::runtime::{Builder, Runtime};

pub struct AppState {
    runtime: Runtime,
    exporter: PrometheusExporter,
}

fn init_meter() -> PrometheusExporter {
    opentelemetry_prometheus::exporter().init()
}

impl AppState {
    pub fn init() -> AppState {
        let exporter = init_meter();
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let state = AppState { runtime, exporter };
        state
    }
    pub fn gather(&self) -> Vec<MetricFamily> {
        self.exporter.registry().gather()
    }
    pub fn get_runtime(&self) -> &Runtime {
        return &self.runtime;
    }
    pub fn _shutdown(self) {
        self.runtime.shutdown_background();
    }
}
