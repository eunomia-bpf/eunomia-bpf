# bpf-loader-rs

The **bpf-loader** is the core runtime library of eunomia-bpf, written in Rust. It provides dynamic loading and management of eBPF programs using a JSON-based skeleton format.

## Overview

`bpf-loader-rs` is the Rust implementation of the BPF loader, providing:

- **Dynamic Loading**: Load eBPF programs from JSON skeleton files
- **BTF Verification**: Type-safe operations using BPF Type Format
- **Program Lifecycle**: Complete management (load, attach, poll, detach)
- **Data Export**: Multiple mechanisms (ring buffers, perf events, map sampling)
- **CO-RE Support**: Compile Once - Run Everywhere portability

## Components

- `bpf-loader-lib`: The core library implementation
- `bpf-loader-cli`: CLI tool for running skeletons with auto-generated command-line arguments
- `bpf-loader-c-wrapper`: C library wrapper providing the same interface as the previous C++ version

## Quick Start

### Build

```bash
# Build all components
cargo build

# Build release version (optimized)
cargo build --release

# Run CLI tool
cargo run -- <path-to-skeleton.json>
```

**Output locations:**
- Debug: `target/debug/libeunomia.{a,so}`
- Release: `target/release/libeunomia.{a,so}`

### Run Examples

Example programs are provided in `bpf-loader-lib/assets/`:
- `bootstrap.json` - Process execution tracer
- `runqlat.json` - Run queue latency histogram

```bash
# Run bootstrap example
cargo run -- bpf-loader-lib/assets/bootstrap.json

# Without debug logs
cargo run -- --no-log bpf-loader-lib/assets/bootstrap.json
```

**Example output:**
```console
$ cargo run -- bpf-loader-lib/assets/bootstrap.json
TIME     PID    PPID   EXIT_CODE DURATION_NS COMM   FILENAME EXIT_EVENT
16:58:31  506334 486903 0        0           "sh"   "/bin/sh" false
16:58:31  506335 506334 0        0           "which" "/usr/bin/which" false
16:58:31  506335 506334 0        754015      "which" ""      true
16:58:31  506334 486903 0        1903616     "sh"   ""       true
```

## Architecture

### Three-Phase Lifecycle

#### 1. Build Phase (`BpfSkeletonBuilder`)
```rust
let builder = BpfSkeletonBuilder::new(json_skeleton)?;
let preload = builder.build()?;
```
- Parse and validate JSON skeleton
- Load BTF information
- Verify type compatibility
- Open BPF object (not yet loaded into kernel)

#### 2. Load Phase (`PreLoadBpfSkeleton`)
```rust
let skeleton = preload.load_and_attach()?;
```
- Load BPF programs into kernel
- Attach to specified hooks/tracepoints
- Create lifecycle management links
- Return polling-ready skeleton

#### 3. Poll Phase (`BpfSkeleton`)
```rust
skeleton.wait_and_poll_to_handler(
    ExportFormatType::PlainText,
    None,  // Use default handler
    None   // No custom context
)?;
```
- Poll data from kernel
- Export through unified handler interface
- Control via handles (pause/resume/stop)

### Core Modules

**`skeleton/`** - BPF Program Lifecycle
- `builder.rs` - Skeleton construction from JSON
- `preload/` - Pre-load verification and attachment
  - `attach.rs` - Program attachment logic
  - `arg_parser.rs` - CLI argument generation
- `handle.rs` - Thread-safe polling control
- `poller/` - Data polling implementations

**`export_event/`** - Data Export Framework
- Ring buffer export (high-performance)
- Perf event array export (per-CPU buffered)
- Map sampling export (periodic statistics)
- Unified `EventExporter` and `EventHandler` interfaces

**`meta/`** - JSON Schema Definitions
- `EunomiaObjectMeta` - Top-level skeleton metadata
- `BpfSkelMeta` - BPF program/map definitions
- `MapMeta` - Map metadata and export configuration
- `RunnerConfig` - Runtime configuration

**`btf_container.rs`** - BTF Management
- Loads BTF from `/sys/kernel/btf/vmlinux` or custom paths
- Provides type information for CO-RE relocations
- Validates program types against kernel BTF

**`elf_container.rs`** - ELF Data Management
- Holds compiled eBPF bytecode
- Manages program sections
- Supports base64-encoded ELF in JSON

## JSON Skeleton Format

The loader consumes JSON skeletons with this structure:

```json
{
  "bpf_skel": {
    "obj_name": "program_name",
    "data": "base64_encoded_elf_data",
    "maps": [...],
    "progs": [...]
  },
  "export_types": [...],
  "config": {
    "poll_timeout_ms": 100
  }
}
```

### Multiple Export Types Support

When `enable_multiple_export_types` is `true` in `EunomiaObjectMeta`, multiple export types are supported. Otherwise the behavior is compatible with the old version (the `export_types` field will be ignored if multiple export types is enabled).

Each map's `export_config` can be one of four variants:

1. **`"no_export"`** (String) - Map not used for exporting

2. **`"default"`** (String) - For sample maps only
   - Export type read from BTF and map's `btf_value_type_id`

3. **`{"btf_type_id": <u32>}`** (Object) - All map types
   - Use specified BTF type for export
   - Ring buffer/perf event: interpret kernel data
   - Sample maps: interpret map values

4. **`{"custom_members": [...]}`** (Object) - All map types
   - Custom struct with specified members
   - Each member: `{"name": <String>, "offset": <usize>, "btf_type_id": <u32>}`

## Data Export Mechanisms

### Ring Buffer Export
**Best for:** High-throughput event streaming
- Lock-free, per-CPU ring buffers
- Low overhead, high performance
- Automatic event batching

### Perf Event Array Export
**Best for:** Per-CPU buffered events with metadata
- Per-CPU buffers with page alignment
- Event metadata and sampling
- Higher overhead than ring buffers

### Map Sampling Export
**Best for:** Periodic statistics and histograms
- Polls BPF maps at intervals
- Automatic histogram generation
- Text-based output (ASCII histograms)

## Advanced Usage

### Custom Event Handler

```rust
use bpf_loader_lib::export_event::{EventHandler, EventHandlerContext};

struct MyHandler;

impl EventHandler for MyHandler {
    fn handle_event(
        &self,
        _context: Option<Arc<dyn Any>>,
        data: &[u8]
    ) -> Result<()> {
        // Custom processing
        println!("Received {} bytes", data.len());
        Ok(())
    }
}

// Use custom handler
skeleton.wait_and_poll_to_handler(
    ExportFormatType::PlainText,
    Some(Arc::new(MyHandler)),
    None
)?;
```

### Controlled Polling

```rust
use std::thread;
use std::time::Duration;

// Get control handle
let handle = skeleton.create_poll_handle();

// Control from another thread
let control_thread = thread::spawn(move || {
    thread::sleep(Duration::from_secs(5));
    handle.pause();

    thread::sleep(Duration::from_secs(2));
    handle.resume();

    thread::sleep(Duration::from_secs(5));
    handle.terminate();
});

// Poll in main thread
skeleton.wait_and_poll_to_handler(
    ExportFormatType::PlainText,
    None,
    None
)?;

control_thread.join().unwrap();
```

### Accessing Map/Program FDs

```rust
// Get map file descriptor
if let Some(fd) = skeleton.get_map_fd("config_map") {
    // Use fd for custom operations
}

// Get program file descriptor
if let Some(fd) = skeleton.get_prog_fd("my_prog") {
    // Use fd for custom operations
}
```

## Testing

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p bpf-loader-lib

# Skip BPF loading tests (for CI/containers)
cargo test --features no-load-bpf-tests

# With debug logging
RUST_LOG=debug cargo test
```

## Integration

### With Compiler (ecc)
```bash
# Compile eBPF program to JSON skeleton
ecc program.bpf.c -o program.json

# Load and run with bpf-loader
cargo run -- program.json
```

### With ecli
The `ecli` tool uses this library to load programs from URLs, OCI images, and local files.

### With C/C++ Projects
```c
#include "bpf_loader.h"

int handle = bpf_loader_load_json("program.json");
bpf_loader_start_polling(handle, callback_fn);
bpf_loader_destroy(handle);
```

## Troubleshooting

### BTF Not Found
```
Error: BTF file not found at /sys/kernel/btf/vmlinux
```
**Solution:**
- Ensure kernel has BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Or set: `export BTF_FILE_PATH=/path/to/btf`

### Permission Denied
```
Error: Failed to load BPF program: Permission denied
```
**Solution:**
- Run with `sudo` or appropriate capabilities (`CAP_BPF`, `CAP_PERFMON`)
- Check kernel version supports required BPF features

### Type Mismatch
```
Error: Type descriptor mismatch for field 'pid'
```
**Solution:**
- Recompile eBPF program with matching type definitions
- Ensure JSON skeleton has correct export type descriptors

## Performance

### Benchmarks
Typical performance on modern systems:
- **Ring Buffer**: 1M+ events/sec with <5% CPU overhead
- **Perf Event**: 500K+ events/sec with ~10% CPU overhead
- **Map Sampling**: Negligible overhead, depends on interval

### Optimization Tips
1. Use ring buffers over perf events (2-3x lower overhead)
2. Adjust polling timeout based on latency requirements
3. Batch event processing in handlers
4. Set appropriate map sampling intervals (≥1000ms for histograms)

## Documentation

For more information, see:
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF Type Format](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [CO-RE Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)

## License

MIT LICENSE - See [LICENSE](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/LICENSE)
