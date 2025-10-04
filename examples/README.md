# eunomia-bpf Examples

Collection of example eBPF programs demonstrating various eunomia-bpf capabilities and use cases.

## Overview

This directory contains:
- **`bpftools/`** - Production-ready eBPF tools (similar to BCC tools)
- **`tests/`** - Integration tests for ecli and compiler
- **`simple-runner-rs/`** - Example showing how to use eunomia-bpf library in Rust projects

## Quick Start

### Compile an Example

```bash
cd examples/bpftools/bootstrap
ecc bootstrap.bpf.c event.h
```

### Run an Example

```bash
# Run locally
sudo ecli run examples/bpftools/bootstrap/package.json

# Run from registry
sudo ecli run ghcr.io/eunomia-bpf/bootstrap:latest
```

## Example Programs

### minimal - Minimal eBPF Program

**Location:** `bpftools/minimal/`

The simplest possible eBPF program that does something useful.

**What it does:**
- Traces process creation via `tp/sched/sched_process_exec`
- Prints PID and process name
- Demonstrates minimal boilerplate

**Code:**
```c
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec* ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("New process: PID %d\n", pid);
    return 0;
}
```

**Run:**
```bash
cd bpftools/minimal
ecc minimal.bpf.c
sudo ecli run package.json
```

See [bpftools/minimal/README.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/examples/bpftools/minimal/README.md) for details.

---

### bootstrap - Process Lifecycle Tracer

**Location:** `bpftools/bootstrap/`

A realistic eBPF application that tracks process lifecycle.

**What it traces:**
- Process execution (`exec()` syscalls)
- Process exit events
- Filename, PID, PPID
- Exit status and process duration

**Features:**
- Ring buffer for efficient event delivery
- Automatic CLI argument generation
- Export type definitions
- CO-RE portability

**Output:**
```
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT
22:01:04  46310  2915    0          0            sh      /bin/sh   0
22:01:04  46311  46310   0          0            which   /usr/bin/which 0
22:01:04  46311  46310   0          2823776      which             1
```

**Run:**
```bash
cd bpftools/bootstrap
ecc bootstrap.bpf.c event.h
sudo ecli run package.json
```

See [bpftools/bootstrap/README.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/examples/bpftools/bootstrap/README.md) for details.

---

### opensnoop - File Open Tracer

**Location:** `bpftools/opensnoop/`

Traces `open()` syscalls system-wide with detailed information.

**What it traces:**
- File opens across all processes
- PID, process name, filename
- File flags and modes
- Success/failure status

**Features:**
- Perf event array for data export
- Prometheus metrics integration via `config.yaml`
- Filtering options (by PID, filename pattern)

**Prometheus Integration:**

`config.yaml`:
```yaml
programs:
- name: opensnoop
  metrics:
    counters:
    - name: eunomia_file_open_counter
      description: File open events
      labels:
      - name: pid
      - name: comm
      - name: filename
        from: fname
  compiled_ebpf_filename: package.json
```

**Run:**
```bash
cd bpftools/opensnoop
ecc opensnoop.bpf.c event.h
sudo ecli run package.json

# With eunomia-exporter for Prometheus
eunomia-exporter --config config.yaml
```

See [bpftools/opensnoop/README.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/examples/bpftools/opensnoop/README.md) for details.

---

### sigsnoop - Signal Tracer (with WASM)

**Location:** `bpftools/sigsnoop/`

Traces signals generated system-wide, demonstrating WebAssembly integration.

**What it traces:**
- Standard and real-time signals
- Source and target PID
- Signal number and name
- Return status

**WebAssembly Features:**
- Control plane written in C, compiled to Wasm
- Command-line argument parsing in Wasm
- Signal filtering logic in Wasm
- Portable across architectures

**Build WASM Module:**

```bash
cd bpftools/sigsnoop

# Generate WASM skeleton (already included)
docker run -it -v $(pwd):/src/ \
  ghcr.io/eunomia-bpf/ecc-$(uname -m):latest gen-wasm-skel

# Build WASM module
docker run -it -v $(pwd):/src/ \
  ghcr.io/eunomia-bpf/ecc-$(uname -m):latest build-wasm
```

**Run:**
```bash
# Show help
sudo ecli run app.wasm -h

# Run with all signals
sudo ecli run app.wasm

# Filter by PID
sudo ecli run app.wasm -p 1641

# Failed signals only
sudo ecli run app.wasm -x

# Kill signals only
sudo ecli run app.wasm -k
```

**Output:**
```json
{"pid":185539,"tpid":185538,"sig":17,"ret":0,"comm":"cat","sig_name":"SIGCHLD"}
{"pid":185540,"tpid":185538,"sig":17,"ret":0,"comm":"grep","sig_name":"SIGCHLD"}
```

See [bpftools/sigsnoop/README.md](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/examples/bpftools/sigsnoop/README.md) for details.

---

### runqlat - Scheduler Latency Histogram

**Location:** `bpftools/runqlat/`

Measures scheduler run queue latency as a histogram.

**What it measures:**
- Time processes spend waiting in run queue
- Latency distribution across all CPUs
- Histogram buckets (microseconds)

**Features:**
- Hash map for histogram data
- Automatic histogram generation and printing
- Per-CPU statistics
- Logarithmic bucketing

**Output:**
```
     usecs          : count    distribution
     0 -> 1         : 0        |                              |
     2 -> 3         : 5        |*****                         |
     4 -> 7         : 20       |********************          |
     8 -> 15        : 32       |********************************|
    16 -> 31        : 18       |******************            |
    32 -> 63        : 8        |********                      |
```

**Run:**
```bash
cd bpftools/runqlat
ecc runqlat.bpf.c
sudo ecli run package.json
```

---

### tcpstates - TCP State Machine Tracer

**Location:** `bpftools/tcpstates/`

Traces TCP connection state changes.

**What it traces:**
- TCP state transitions (ESTABLISHED, CLOSE_WAIT, etc.)
- Source/dest IP and port
- Process PID and name
- Connection duration

**Run:**
```bash
cd bpftools/tcpstates
ecc tcpstates.bpf.c
sudo ecli run package.json
```

---

### profile - CPU Profiler

**Location:** `bpftools/profile/`

CPU profiler using perf events.

**What it does:**
- Samples stack traces at regular intervals
- Aggregates by function/stack
- Generates flame graphs

**Run:**
```bash
cd bpftools/profile
ecc profile.bpf.c
sudo ecli run package.json --duration 30
```

---

### XDP Examples

**Location:** `bpftools/xdp/`

XDP (eXpress Data Path) packet processing examples.

**Examples:**
- **xdp_drop** - Drop specific packets
- **xdp_pass** - Pass-through with monitoring
- **xdp_redirect** - Redirect packets to different interface

**Run:**
```bash
cd bpftools/xdp
ecc xdp_drop.bpf.c
sudo ecli run package.json --interface eth0
```

---

### TC (Traffic Control) Examples

**Location:** `bpftools/tc/`

Traffic control and shaping examples.

**Examples:**
- Packet filtering
- Bandwidth limiting
- QoS marking

---

### LSM (Linux Security Module) Example

**Location:** `bpftools/lsm-connect/`

Security monitoring using LSM hooks.

**What it does:**
- Monitors TCP connect attempts
- Blocks connections based on policy
- Logs security events

---

### kprobe and fentry Examples

**Location:** `bpftools/kprobe-link/`, `bpftools/fentry-link/`

Demonstrates kernel function tracing:
- **kprobe** - Traditional kernel probes
- **fentry/fexit** - Modern BPF trampolines (lower overhead)

## Building Examples

### Build All Examples

```bash
cd examples/bpftools
make all
```

### Build Specific Example

```bash
cd examples/bpftools/bootstrap
make
# or
ecc bootstrap.bpf.c event.h
```

### Clean

```bash
cd examples/bpftools
make clean
```

## Testing Examples

### Run Integration Tests

```bash
cd examples/tests
make test
```

### Test Specific Example

```bash
cd examples/bpftools/bootstrap
make test
# or
sudo ecli run package.json
```

## Using simple-runner-rs

The `simple-runner-rs` demonstrates programmatic usage of bpf-loader-lib:

```rust
use bpf_loader_lib::skeleton::BpfSkeletonBuilder;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load JSON skeleton
    let json = fs::read_to_string("package.json")?;

    // Build and load
    let builder = BpfSkeletonBuilder::new(&json)?;
    let preload = builder.build()?;
    let skeleton = preload.load_and_attach()?;

    // Poll events
    skeleton.wait_and_poll_to_handler(
        ExportFormatType::PlainText,
        None,
        None
    )?;

    Ok(())
}
```

**Run:**
```bash
cd examples/simple-runner-rs
cargo run -- ../bpftools/bootstrap/package.json
```

## Creating Your Own Example

### 1. Write eBPF Code

`my_tracer.bpf.c`:
```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @export
struct event {
    u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter* ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 2. Define Export Types

`event.h`:
```c
#ifndef __EVENT_H
#define __EVENT_H

struct event {
    unsigned int pid;
    char comm[16];
};

#endif
```

### 3. Compile

```bash
ecc my_tracer.bpf.c event.h
```

### 4. Run

```bash
sudo ecli run package.json
```

## Example Categories

### Tracing
- **bootstrap** - Process lifecycle
- **opensnoop** - File operations
- **sigsnoop** - Signals
- **tcpstates** - Network connections

### Performance
- **runqlat** - Scheduler latency
- **profile** - CPU profiling

### Networking
- **XDP** - Packet processing
- **TC** - Traffic control

### Security
- **LSM** - Security monitoring
- **kprobe** - Kernel function tracing

## Troubleshooting

### Compilation Errors

```
Error: Failed to compile BPF program
```
**Solution:**
- Check kernel headers: `ls /usr/include/linux/`
- Install: `apt install linux-headers-$(uname -r)`

### Loading Errors

```
Error: Failed to load BPF program: Invalid argument
```
**Solution:**
- Check kernel version: `uname -r` (need 5.8+ for full features)
- Enable BTF: `CONFIG_DEBUG_INFO_BTF=y`
- Run with sudo

### No Events

```
Program running but no output
```
**Solution:**
- Trigger the event (e.g., run commands for exec tracer)
- Check filters (PID, etc.)
- Verify map/program attach points

## Resources

- [libbpf examples](https://github.com/libbpf/libbpf-bootstrap/tree/master/examples)
- [BCC tools](https://github.com/iovisor/bcc/tree/master/tools)
- [Kernel samples](https://github.com/torvalds/linux/tree/master/samples/bpf)

## Contributing Examples

To contribute a new example:

1. Create directory in `bpftools/<name>/`
2. Add `.bpf.c` source and `.h` headers
3. Create README.md with:
   - Purpose and use case
   - Build instructions
   - Usage examples
   - Sample output
4. Add to this README
5. Submit PR

## License

All examples are MIT licensed - See [LICENSE](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/LICENSE)
