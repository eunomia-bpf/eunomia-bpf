use derivative::Derivative;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Derivative, Debug, Default)]
pub struct ExporterConfig {
    pub progtams: Vec<ProgramConfig>,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Default)]
pub struct ProgramConfig {
    pub name: String,
    pub ebpf_data: String,
    pub metrics: MetricsConfig,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Default)]
pub struct MetricsConfig {
    pub counters: Vec<CounterConfig>,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Default)]
pub struct CounterConfig {
    pub name: String,
    #[derivative(Default(value = "Counter of events"))]
    pub description: String,
    pub labels: Vec<LabelConfig>,
}

#[derive(Serialize, Deserialize, Derivative, Debug, Default)]
pub struct LabelConfig {
    pub name: String,
    #[derivative(Default(value = "*"))]
    pub from: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use std::fs;

    #[test]
    fn from_json() {
        let config = json!({
            "progtams": [
                {
                    "name": "test",
                    "ebpf_data": "test",
                    "metrics": {
                        "counters": [
                            {
                                "name": "test",
                                "description": "test",
                                "labels": [
                                    {
                                        "name": "pid",
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        });
        let config: ExporterConfig = serde_json::from_value(config).unwrap();
        let prog_config = config.progtams.get(0).unwrap();
        let json_config = serde_json::to_string(&prog_config).unwrap();
        println!("{}", json_config);
    }
}