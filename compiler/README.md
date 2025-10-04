# eunomia-bpf Compiler (ecc)

The **ecc** (eunomia compiler) is a CO-RE (Compile Once - Run Everywhere) eBPF compiler toolchain that transforms eBPF C source code into distributable JSON/YAML packages. Focus on writing a single eBPF kernel program - nothing more!

## Overview

ecc compiles eBPF programs and automatically generates:
- **Portable packages** with embedded BTF and compressed ELF
- **Metadata extraction** from source code documentation
- **Type information** for userspace data export
- **Multiple output formats**: JSON, YAML, standalone executables, WebAssembly headers

> **Note:** This is the compiler toolchain. For a project template to build new eunomia-bpf applications, see [eunomia-bpf-template](https://github.com/eunomia-bpf/ebpm-template). For the runtime, see [eunomia-bpf runtime](https://github.com/eunomia-bpf/eunomia-bpf).

## Quick Start

### Installation

Download pre-built binary:
```bash
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc
chmod +x ecc
sudo mv ecc /usr/local/bin/
```

Or use Docker:
```bash
# For x86_64
docker run -it -v $(pwd):/src ghcr.io/eunomia-bpf/ecc-x86_64:latest

# For ARM64
docker run -it -v $(pwd):/src ghcr.io/eunomia-bpf/ecc-aarch64:latest
```

### Basic Usage

```bash
# Compile eBPF program
ecc program.bpf.c

# With export event types
ecc program.bpf.c event.h

# Specify output directory
ecc program.bpf.c -o dist/

# Generate YAML instead of JSON
ecc program.bpf.c --yaml
```

**Example:**
```bash
$ ecc examples/bpftools/bootstrap/bootstrap.bpf.c \
      examples/bpftools/bootstrap/event.h

# Generates:
# - package.json (distributable package)
# - config.json (metadata)
# - output.bpf.o (compiled ELF)
```

## What ecc Does

```
Input: program.bpf.c + event.h
    ↓
[1] Compile to BPF object
    clang -target bpf -O2 -g → output.bpf.o
    ↓
[2] Extract skeleton metadata
    bpftool gen skeleton -j → skeleton JSON
    ↓
[3] Extract BTF types
    bpftool btf dump -j → type info
    ↓
[4] Parse documentation
    clang AST → doc comments
    ↓
[5] Package & compress
    zlib + base64 → package.json
    ↓
Output: Portable, distributable package
```

## Output Formats

### JSON Package (default)
```bash
ecc program.bpf.c
# → package.json
```

Contains:
- Compressed ELF binary (base64-encoded)
- Program/map metadata
- BTF type information
- Documentation from source

**Structure:**
```json
{
  "bpf_skel": {
    "obj_name": "bootstrap",
    "data": "eJzt...base64(zlib(ELF))...",
    "maps": [{...}],
    "progs": [{...}]
  },
  "export_types": [{...}],
  "eunomia_version": "1.0.0"
}
```

### YAML Output
```bash
ecc program.bpf.c --yaml
# → package.yaml
```

Same content as JSON but in YAML format.

### Standalone Executable
```bash
ecc program.bpf.c --standalone -o mytool
# → mytool (single executable)

./mytool  # Run directly
```

Produces a self-contained executable with embedded eBPF program and runner.

### WebAssembly Header
```bash
ecc program.bpf.c --wasm-header
# → ebpf_program.h
```

Generates C header for Wasm integration:
```c
const char* get_ebpf_program() {
    return R"JSON({...})JSON";
}
```

### Tailored BTF (btfgen)
```bash
ecc program.bpf.c --btfgen
# → btfgen.tar.gz
```

Generates minimal BTF files for multiple kernel versions, enabling compatibility with older kernels without full BTF support.

## Advanced Features

### Export Type Annotations

Mark structs for automatic export with `@export` annotation:

```c
/// @export
struct event {
    u32 pid;
    u32 ppid;
    char comm[16];
};
```

ecc will:
1. Extract the struct from BTF
2. Add type information to package
3. Enable automatic userspace parsing

### Documentation Extraction

Document your eBPF programs with comments:

```c
/// Trace process execution events
/// This program monitors when new processes are created
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // ...
}
```

ecc extracts documentation and includes it in the package metadata.

### Custom Compiler Flags

```bash
# Add include paths
ecc program.bpf.c -a "-I/custom/include"

# Define macros
ecc program.bpf.c -a "-DDEBUG=1" -a "-DMAX_ENTRIES=1024"

# Use custom clang
ecc program.bpf.c --clang-bin /opt/clang-15/bin/clang
```

### BTFgen for Kernel Compatibility

Generate tailored BTF for old kernels:

```bash
# Download btfhub archive and generate minimal BTF
ecc program.bpf.c --btfgen

# Use custom btfhub location
ecc program.bpf.c --btfgen --btfhub-archive /path/to/btfhub
```

This creates minimal BTF files for different kernel versions, significantly reducing size while maintaining compatibility.

## Compilation Pipeline

### Step 1: BPF Compilation

```bash
clang -g -O2 -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/bpf \
  -c program.bpf.c \
  -o output.bpf.o

llvm-strip -g output.bpf.o
```

**Key flags:**
- `-target bpf`: Generate BPF bytecode
- `-g`: Include debug info (required for BTF)
- `-O2`: Optimization (required by BPF verifier)
- `-D__TARGET_ARCH_xxx`: Architecture macros

### Step 2: Metadata Extraction

**Skeleton generation:**
```bash
bpftool gen skeleton output.bpf.o -j > skeleton.json
```

Extracts:
- Program names and types
- Map definitions
- Attach point information

**BTF extraction:**
```bash
bpftool btf dump file output.bpf.o format c -j > btf.json
```

Extracts:
- Type information
- Struct definitions
- Export types (marked with `@export`)

### Step 3: Documentation Parsing

Uses Clang AST to extract:
- Function documentation
- Parameter descriptions
- Usage notes

### Step 4: Packaging

```rust
// Compress ELF
let compressed = zlib::encode(elf_data)?;
let encoded = base64::encode(compressed);

// Create package
let package = {
    "bpf_skel": {
        "data": encoded,
        "maps": [...],
        "progs": [...]
    },
    "export_types": [...],
    "eunomia_version": "1.0.0"
};

fs::write("package.json", serde_json::to_string(&package)?)?;
```

**Result:** Compressed package ~50% smaller than original ELF.

## Building from Source

### Dependencies

**Ubuntu/Debian:**
```bash
apt install clang libelf1 libelf-dev zlib1g-dev llvm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**CentOS/Fedora:**
```bash
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Steps

```bash
# Clone with submodules
git clone --recursive https://github.com/eunomia-bpf/eunomia-bpf.git
cd eunomia-bpf/compiler

# Or update submodules if already cloned
git submodule update --init --recursive --remote

# Build
make

# Install
sudo make install

# Verify
ecc -h
```

### Build Docker Image

```bash
cd compiler
make docker

# Use it
docker run -v $(pwd):/src ghcr.io/eunomia-bpf/ecc:latest program.bpf.c
```

## CLI Reference

```
eunomia-bpf compiler

Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]

Arguments:
  <SOURCE_PATH>           Path to the .bpf.c source file
  [EXPORT_EVENT_HEADER]   Path to export event header (.h file)

Options:
  -o, --output-path <DIR>       Output directory for generated files
  -v, --verbose                 Show detailed logs
  -y, --yaml                    Output YAML instead of JSON

  --wasm-header                 Generate WebAssembly header
  -s, --standalone              Generate standalone executable
  -b, --btfgen                  Generate tailored BTF for old kernels

  --btfhub-archive <PATH>       BTFhub archive location
                                [default: ~/.eunomia/btfhub-archive]

  -a, --additional-cflags <FLAG> Additional C compiler flags (repeatable)
  -c, --clang-bin <PATH>        Path to clang binary
                                [default: clang]
  -l, --llvm-strip-bin <PATH>   Path to llvm-strip binary
                                [default: llvm-strip]

  --header-only                 Generate object for header definitions only
  --no-generate-package-json    Skip package.json generation

  -h, --help                    Print help
```

## Examples

### Basic Tracepoint Program

**bootstrap.bpf.c:**
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

/// Trace process execution
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
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

**Compile:**
```bash
ecc bootstrap.bpf.c event.h

# Run with ecli
sudo ecli run package.json
```

### XDP Program

```c
SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP)
        return XDP_DROP;

    return XDP_PASS;
}
```

**Compile:**
```bash
ecc xdp_drop.bpf.c -o xdp/
```

## Integration

### With bpf-loader

```bash
# Compile
ecc program.bpf.c

# Load and run
sudo ecli run package.json
```

### With OCI Registry

```bash
# Compile
ecc program.bpf.c

# Push to registry
ecli push package.json ghcr.io/yourorg/tool:v1.0

# Others can pull and run
ecli pull ghcr.io/yourorg/tool:v1.0
sudo ecli run ghcr.io/yourorg/tool:v1.0
```

### Programmatic Usage (Rust)

```rust
use std::process::Command;

// Compile eBPF program
let output = Command::new("ecc")
    .args(&["program.bpf.c", "event.h", "-o", "dist/"])
    .output()?;

if !output.status.success() {
    eprintln!("Compilation failed: {}", String::from_utf8_lossy(&output.stderr));
}

// Load the generated package
let package = std::fs::read_to_string("dist/package.json")?;
// Use with bpf-loader-lib...
```

## Troubleshooting

### Clang Not Found
```
Error: Failed to run clang: No such file or directory
```
**Solution:**
```bash
# Install clang
apt install clang  # or dnf install clang

# Or specify path
ecc program.bpf.c --clang-bin /usr/bin/clang-15
```

### BTF Extraction Failed
```
Error: Failed to dump BTF from compiled file
```
**Solution:**
- Ensure object compiled with `-g` (ecc does this automatically)
- Check bpftool is available: `which bpftool`
- Verify kernel has BTF support: `ls /sys/kernel/btf/vmlinux`

### Export Struct Not Found
```
Error: Struct 'event' marked with @export but not found in BTF
```
**Solution:**
Ensure struct is actually used in code:
```c
// Add unused pointer to force BTF emission
__attribute__((unused)) static struct event *__event_ptr;

/// @export
struct event {
    u32 pid;
};
```

### Package Too Large
```
Warning: package.json is 5MB, consider optimization
```
**Solution:**
- ecc strips debug symbols automatically
- Check for unnecessary includes
- Verify BTF data isn't duplicated

## Roadmap

- [X] Support tracepoints, fentry, kprobe, LSM
- [X] Ring buffer and perf event output
- [X] Easy compilation without code modification
- [X] Wasm support
- [X] JSON redesign
- [X] libbpf features integration
- [X] BTFgen for old kernels
- [ ] Enhanced XDP support
- [ ] Better uprobe support
- [ ] Improved old kernel compatibility

## Resources

### Documentation
- [Detailed Usage Guide](https://eunomia-bpf.github.io/ecc/usage.html) - Complete documentation
- [Template Project](https://github.com/eunomia-bpf/ebpm-template)

### Related Tools
- [bpftool](https://github.com/libbpf/bpftool) - BPF introspection tool
- [libbpf](https://github.com/libbpf/libbpf) - BPF CO-RE library
- [CO-RE Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)

### Runtime
- [eunomia-bpf Runtime](https://github.com/eunomia-bpf/eunomia-bpf) - Load and run compiled packages
- [ecli](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/ecli) - CLI tool for running packages

## License

MIT LICENSE - See [LICENSE](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/LICENSE)
