# eunomia-bpf SDKs

Language-specific SDKs and integrations for eunomia-bpf.

## Overview

This directory contains SDKs and integrations that make it easier to use eunomia-bpf from different languages and platforms.

## Available SDKs

### eunomia-rs (Rust SDK)

**Location:** `eunomia-rs/`

High-level Rust API for working with eunomia-bpf programs.

**Features:**
- Type-safe program loading
- Ergonomic API design
- Zero-cost abstractions
- Integration with Rust ecosystem

**Example:**
```rust
use eunomia_rs::{EunomiaProgram, ProgramConfig};

// Load program
let program = EunomiaProgram::from_json("program.json")?;

// Run with default config
program.run()?;

// Or with custom configuration
let config = ProgramConfig {
    args: vec!["--pid", "1234"],
    export_format: ExportFormat::Json,
    ..Default::default()
};

program.with_config(config).run()?;
```

### eunomia-otel (OpenTelemetry Integration)

**Location:** `eunomia-otel/`

Export eBPF events to OpenTelemetry for observability platforms.

**Features:**
- Automatic span/metric generation from eBPF events
- Support for gRPC and HTTP exporters
- Attribute mapping from event fields
- Batching and compression

**Example:**
```rust
use eunomia_otel::{OtelExporter, OtelConfig};
use std::sync::Arc;

// Configure OpenTelemetry exporter
let exporter = OtelExporter::new(OtelConfig {
    endpoint: "http://localhost:4317",
    service_name: "my-ebpf-tracer",
    protocol: Protocol::Grpc,
})?;

// Load program with OTel handler
let program = EunomiaProgram::from_json("program.json")?
    .with_handler(Arc::new(exporter));

// Events automatically exported to OTel
program.run()?;
```

**Supported Backends:**
- Jaeger
- Prometheus
- Grafana Tempo
- Any OTLP-compatible backend

## Planned SDKs

### Python SDK (eunomia-py)

**Status:** Planned

Python bindings using PyO3.

```python
from eunomia import EunomiaProgram

# Load and run program
program = EunomiaProgram.from_json("program.json")
program.run()

# With custom handler
def handle_event(data):
    print(f"Received event: {data}")

program.on_event(handle_event).run()
```

### Go SDK (eunomia-go)

**Status:** Planned

Go bindings using CGO.

```go
import "github.com/eunomia-bpf/eunomia-go"

// Load program
program, err := eunomia.LoadJSON("program.json")
if err != nil {
    log.Fatal(err)
}

// Run program
if err := program.Run(); err != nil {
    log.Fatal(err)
}
```

### JavaScript/Node SDK (eunomia-js)

**Status:** Planned

Node.js bindings using NAPI.

```javascript
const { EunomiaProgram } = require('eunomia-bpf');

// Load and run
const program = await EunomiaProgram.fromJSON('program.json');
await program.run();

// Event handling
program.on('event', (data) => {
  console.log('Event:', data);
});
```

## Integration Examples

### eunomia-otel Examples

#### Exporting to Jaeger

```rust
use eunomia_otel::OtelExporter;

let exporter = OtelExporter::builder()
    .endpoint("http://jaeger:4317")
    .service_name("ebpf-tracer")
    .build()?;

let program = EunomiaProgram::from_json("program.json")?
    .with_handler(Arc::new(exporter));

program.run()?;
```

#### Custom Span Attributes

```rust
use eunomia_otel::{OtelExporter, AttributeMapping};

let exporter = OtelExporter::builder()
    .endpoint("http://localhost:4317")
    .attribute_mapping(AttributeMapping {
        // Map event fields to span attributes
        mappings: vec![
            ("pid", "process.pid"),
            ("comm", "process.name"),
            ("latency_ns", "span.duration"),
        ].into_iter().collect(),
    })
    .build()?;
```

#### Metrics Export

```rust
use eunomia_otel::{OtelExporter, ExportMode};

let exporter = OtelExporter::builder()
    .endpoint("http://prometheus-otlp:4317")
    .export_mode(ExportMode::Metrics)  // Export as metrics instead of spans
    .metric_prefix("ebpf.")
    .build()?;

// eBPF events become metrics:
// ebpf.exec_count{pid="1234", comm="bash"} 1
// ebpf.latency_ns{operation="exec"} 1234567
```

## Development

### Building

```bash
# Build all SDKs
cd eunomia-sdks
cargo build --all

# Build specific SDK
cargo build -p eunomia-rs
cargo build -p eunomia-otel
```

### Testing

```bash
# Run all tests
cargo test --all

# Test specific SDK
cargo test -p eunomia-otel

# With integration tests
cargo test --all --features integration-tests
```

### Examples

```bash
# Run eunomia-otel example
cd eunomia-otel
cargo run --example jaeger_export

# Run eunomia-rs example
cd eunomia-rs
cargo run --example simple_load
```

## Contributing

To add a new SDK:

1. Create new directory: `eunomia-sdks/<sdk-name>/`
2. Add to workspace in `Cargo.toml`
3. Implement core traits from `eunomia-rs`
4. Add documentation and examples
5. Submit PR

See [CONTRIBUTING.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/CONTRIBUTING.md) for guidelines.

## Resources

- [eunomia-bpf Core](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/bpf-loader-rs) - Core runtime library
- [ecli](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/ecli) - CLI tool
- [OpenTelemetry](https://opentelemetry.io/) - Observability framework

## License

MIT LICENSE - See [LICENSE](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/LICENSE)
