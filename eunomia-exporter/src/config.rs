use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ExporterConfig {
    pub programs: Vec<ProgramConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct ProgramConfig {
    pub name: String,
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub ebpf_data: String,
    #[serde(default)]
    pub compiled_ebpf_filename: String,
}

impl ExporterConfig {
    fn load_ebpf_json_data(&mut self) -> Result<()> {
        for prog in &mut self.programs {
            if !prog.ebpf_data.is_empty() {
                continue;
            }
            if prog.compiled_ebpf_filename.is_empty() {
                return Err(anyhow!("cannot find ebpf program data"));
            }
            prog.ebpf_data = fs::read_to_string(&prog.compiled_ebpf_filename)?;
        }
        Ok(())
    }
    pub fn from_file(filename: &str) -> Result<ExporterConfig> {
        let res = fs::read_to_string(filename);
        match res {
            Ok(data) => {
                let mut config: ExporterConfig = if filename.ends_with(".json") {
                    serde_json::from_str(&data)?
                } else {
                    serde_yaml::from_str(&data)?
                };
                config.load_ebpf_json_data()?;
                Ok(config)
            }
            Err(e) => Err(anyhow!("cannot read config file: {}", e)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct MetricsConfig {
    pub counters: Vec<CounterConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct CounterConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub labels: Vec<LabelConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct LabelConfig {
    pub name: String,
    #[serde(default)]
    pub from: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn from_json() {
        let config = json!({
            "programs": [
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
        let prog_config = config.programs.get(0).unwrap();
        let _ = serde_json::to_string(&prog_config).unwrap();
    }

    #[test]
    fn load_from_example() {
        let _ = ExporterConfig::from_file("examples/opensnoop/opensnoop.yaml").unwrap();
    }
}
