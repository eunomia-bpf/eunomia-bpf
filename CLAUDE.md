# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eunomia-bpf is a dynamic loading library/runtime and compile toolchain framework designed to help build and distribute eBPF programs more easily. It simplifies writing, building, and distributing eBPF programs with CO-RE (Compile Once - Run Everywhere) support and WebAssembly integration.

## Key Commands

### Building the Project

```bash
# Build all components
make all

# Build individual components
make bpf-loader-rs    # Build the core runtime library
make ecli            # Build the CLI tool
make ecc             # Build the compiler

# Clean all build artifacts
make clean
```

### Running Tests

```bash
# Run all tests in bpf-loader-rs
cd bpf-loader-rs && make test

# Run compiler tests with coverage and linting
cd compiler && make test

# Run integration tests
cd examples/tests && make test
```

### Development Commands

```bash
# Install system dependencies
make install-deps

# Run linting (in compiler directory)
cd compiler && cargo clippy --all-features
cd compiler && cargo fmt --check

# Build debug versions
cd bpf-loader-rs && make build-debug

# Build and install locally
make -C ecli install
make -C compiler install
```

### Using the Tools

```bash
# Compile an eBPF program
./ecc your_program.bpf.c

# Run an eBPF program
sudo ./ecli run package.json

# Run from URL
sudo ./ecli run https://example.com/package.json

# Start server mode
sudo ./ecli-server

# Client operations
./ecli client start program.json
./ecli client log 1
```

## High-Level Architecture

The project consists of three main components that work together:

### 1. BPF Loader Library (`bpf-loader-rs/`)
The core runtime that handles:
- Dynamic loading of eBPF programs using a JSON skeleton format
- Managing eBPF program lifecycle (load, attach, poll data)
- Exporting data from kernel to userspace via ring buffers, perf events, or map sampling
- Type verification using BTF information

Key modules:
- `skeleton/`: BPF program management and lifecycle
- `export_event/`: Data export handlers for different map types
- `meta/`: JSON skeleton format definitions
- `btf_container/` and `elf_container/`: BTF and ELF data handling

### 2. Compiler Toolchain (`compiler/`)
Compiles C/C++ eBPF source code and generates distributable packages:
- Uses Clang with CO-RE support for compilation
- Extracts BTF information for portability
- Generates JSON metadata describing the program
- Supports multiple output formats (JSON, YAML, WASM, standalone)

### 3. CLI Tool (`ecli/`)
Provides user interface and program management:
- Run eBPF programs from local files, URLs, or OCI images
- Client-server architecture for remote management
- Task manager for handling multiple running programs

## Data Flow

1. **Development**: Write eBPF C code → Compile with `ecc` → Generate package (JSON/YAML)
2. **Distribution**: Package can be shared via URL, OCI registry, or local file
3. **Runtime**: `ecli` loads package → BPF loader verifies and loads to kernel → Data exported to userspace

## Important Design Patterns

### JSON Skeleton Format
The project uses a JSON format to describe eBPF programs, containing:
- Program and map metadata
- BTF and ELF data (base64 encoded)
- Export type definitions
- Command-line argument specifications

### Export Mechanisms
- **Ring Buffer**: High-performance event streaming
- **Perf Event Array**: Per-CPU buffered events
- **Map Sampling**: Periodic polling of map data

### Error Handling
- Programs return `Result<T, EunomiaError>` for error propagation
- Custom error types defined in `ecli-lib/src/error.rs`
- Comprehensive error messages for debugging

## Code Style Guidelines

- Rust code follows standard Rust conventions
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- C code for eBPF programs follows kernel style
- Prefer descriptive variable names
- Add documentation comments for public APIs

## Testing Strategy

- Unit tests: Located alongside source files, run with `cargo test`
- Integration tests: In `examples/tests/`, test actual eBPF program compilation and execution
- Coverage: Generated using grcov in compiler tests
- CI: GitHub Actions runs tests on every push

## Common Development Tasks

### Adding a New eBPF Program Type
1. Define the program structure in C
2. Add export type definitions if needed
3. Update the skeleton builder to handle new program type
4. Add tests for the new functionality

### Debugging eBPF Programs
1. Use `bpftool` to inspect loaded programs
2. Check kernel logs with `dmesg` for verifier errors
3. Use the `--verbose` flag with ecli for detailed output
4. Examine the generated JSON skeleton for metadata issues

### Working with BTF
- BTF data is crucial for CO-RE support
- The compiler can generate tailored BTF for better compatibility
- Use `btf_container.rs` for BTF manipulation
- Verify BTF with `bpftool btf dump`