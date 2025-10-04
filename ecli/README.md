# ecli - eunomia-bpf CLI

**ecli** is the command-line tool for loading, running, and managing eBPF programs using eunomia-bpf. It supports local execution, remote deployment via HTTP server, and OCI registry operations.

## Overview

ecli provides multiple ways to run eBPF programs:
- **Native**: Run programs locally on your machine
- **Remote**: Execute programs on remote servers via HTTP API
- **OCI Registry**: Pull/push programs from container registries
- **URL**: Load and run programs directly from URLs

## Architecture

```
┌─────────────┐
│   ecli CLI  │
└──────┬──────┘
       │
       ├─────────────────┐
       │                 │
   [Native]         [HTTP Client]
       │                 │
       ↓                 ↓
┌─────────────┐    ┌──────────────┐
│ bpf-loader  │    │ ecli-server  │
│  (local)    │    │  (remote)    │
└─────────────┘    └──────────────┘
```

## Components

The ecli project consists of four crates:

### 1. `ecli-lib` - Core Library

Core implementation providing:
- **OCI registry operations** (pull, push, login, logout)
- **ecli-http-server** - Server implementation
- **ecli-http-client** - Client for remote execution
- **ecli-native-runner** - Local program execution

**Features:**
- `native-client`: Local BPF program execution (requires `bpf-loader-lib`, `wasm-bpf-rs`)
- `http-client`: Remote execution via HTTP API
- `http-server`: HTTP server implementation

### 2. `client` / `ecli` - CLI Client

Wraps `ecli-http-client` and `ecli-native-client` with configurable features:
- `http` (default): Remote program execution
- `native` (default): Local program execution

**Note:** With only `http` feature enabled, ecli can run on Windows (no BPF dependencies)!

```bash
# Build remote-only client (cross-platform)
cargo build --no-default-features --features http -p client
```

### 3. `server` / `ecli-server` - HTTP Server

Standalone HTTP server for managing eBPF programs remotely.

**Features:**
- Start/stop programs
- Stream logs
- List running programs
- Task management

**Note:** Currently no authorization implemented - use an authorization gateway if needed.

### 4. `server-codegen` - Generated API Code

Auto-generated from `apis.yaml`, providing:
- Server implementation scaffolding
- Client implementation

## Quick Start

### Installation

```bash
# Download latest release
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli

# Or build from source
cd ecli
cargo build --release
sudo cp target/release/ecli /usr/local/bin/
```

### Run Locally (Native)

```bash
# From local file
sudo ecli run program.json

# From OCI registry
sudo ecli run ghcr.io/eunomia-bpf/sigsnoop:latest

# From URL
sudo ecli run https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json
```

**Example output:**
```console
$ sudo ecli run examples/bpftools/bootstrap/package.json
TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    FILENAME  EXIT_EVENT
22:01:04  46310  2915    0          0            sh      /bin/sh   0
22:01:04  46311  46310   0          0            which   /usr/bin/which 0
22:01:04  46311  46310   0          2823776      which             1
22:01:04  46310  2915    0          6288891      sh                1
```

### Start Server

```bash
# Start HTTP server
sudo ecli-server
# Listening on 127.0.0.1:8527
```

### Remote Execution

```bash
# Start program remotely
$ ecli client --endpoint http://127.0.0.1:8527 start ./program.json
1  # Returns program handle

# Get logs
$ ecli client --endpoint http://127.0.0.1:8527 log 1
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
16:03:16 EXEC  sh               51857   1711    /bin/sh
16:03:16 EXIT  sh               51857   1711    [0] (1ms)

# Follow logs (like tail -f)
$ ecli client --endpoint http://127.0.0.1:8527 log 1 --follow

# Stop program
$ ecli client --endpoint http://127.0.0.1:8527 stop 1

# List running programs
$ ecli client --endpoint http://127.0.0.1:8527 list
```

## OCI Registry Operations

### Pull from Registry

```bash
# Pull eBPF program from OCI registry
ecli pull ghcr.io/eunomia-bpf/sigsnoop:latest

# Saves to current directory as package.json
```

### Push to Registry

```bash
# Login first (for private registries)
ecli login ghcr.io

# Push package
ecli push package.json ghcr.io/yourorg/mytool:v1.0

# Or with inline credentials
ecli push package.json https://user:token@ghcr.io/yourorg/mytool:v1.0
```

### Logout

```bash
ecli logout ghcr.io
```

## Log Tracking & Streaming

### How It Works

The server maintains a log buffer for each running program:

1. **Log Buffer**: All output (stdout/stderr from Wasm, events from JSON programs) is cached
2. **Timestamps**: Each log entry has a timestamp indicating order
3. **Cursor-Based Fetching**: Client provides cursor (timestamp) to fetch logs from that point
4. **Auto-Cleanup**: Logs before cursor are dropped (no longer needed)

### Example

```bash
# Get latest logs
ecli client log 1

# Follow logs in real-time
ecli client log 1 --follow

# Get logs from specific timestamp
ecli client log 1 --cursor 1234567890
```

## Supported Program Types

### JSON Skeletons

Standard eunomia-bpf JSON packages generated by `ecc`:
```bash
ecli run package.json
```

### WebAssembly Modules

Wasm modules with embedded eBPF:
```bash
ecli run program.wasm
```

### OCI Images

Programs packaged as OCI container images:
```bash
ecli run ghcr.io/org/tool:tag
```

### Direct URLs

Programs hosted on web servers:
```bash
ecli run https://example.com/program.json
```

## HTTP API

The server exposes a RESTful API (defined in `apis.yaml`):

### Start Program

```http
POST /api/v1/ebpf/start
Content-Type: application/json

{
  "program_data": "<base64_or_json>",
  "args": ["--arg1", "value1"]
}

Response: {"id": 1}
```

### Get Logs

```http
GET /api/v1/ebpf/log/{id}?cursor={timestamp}

Response: {
  "logs": [
    {"timestamp": 1234567890, "data": "log line 1"},
    {"timestamp": 1234567891, "data": "log line 2"}
  ]
}
```

### Stop Program

```http
POST /api/v1/ebpf/stop/{id}

Response: {"status": "stopped"}
```

### List Programs

```http
GET /api/v1/ebpf/list

Response: {
  "programs": [
    {"id": 1, "name": "program1", "status": "running"},
    {"id": 2, "name": "program2", "status": "stopped"}
  ]
}
```

## Build Options

### Full-Featured Client

```bash
cd client
cargo build --release
# Includes both native and HTTP support
```

### Remote-Only Client (Windows Compatible)

```bash
cd client
cargo build --release --no-default-features --features http
# No BPF dependencies, can run on Windows
```

### Server

```bash
cd server
cargo build --release
```

## Advanced Usage

### Custom Endpoint

```bash
# Use custom server endpoint
ecli client --endpoint https://remote.example.com:9000 start program.json
```

### Environment Variables

```bash
# Set default endpoint
export ECLI_ENDPOINT=http://localhost:8527

# Use it
ecli client start program.json  # Uses env var
```

### Programmatic Usage (Rust)

```rust
use ecli_lib::runner::{NativeRunner, HttpRunner};

// Native execution
let runner = NativeRunner::new()?;
runner.run("package.json", vec![])?;

// Remote execution
let runner = HttpRunner::new("http://localhost:8527");
let id = runner.start("package.json").await?;
let logs = runner.get_logs(id, 0).await?;
runner.stop(id).await?;
```

## Task Management

The server maintains tasks with:

```rust
pub struct TaskManager {
    tasks: HashMap<TaskId, Task>,
    log_buffer: HashMap<TaskId, LogBuffer>,
}

pub struct Task {
    id: TaskId,
    skeleton: BpfSkeleton,      // Running eBPF program
    handle: PollingHandle,       // Control handle
    created_at: SystemTime,
}

pub struct LogBuffer {
    entries: Vec<LogEntry>,
    max_size: usize,             // Auto-cleanup old entries
}
```

**Features:**
- Automatic log rotation
- Cursor-based log retrieval
- Thread-safe task management
- Graceful shutdown handling

## Security Considerations

### Authentication

**Current State:** No authentication implemented.

**Recommendations:**
- Use reverse proxy with authentication (nginx, Caddy)
- Implement API key validation
- Use mTLS for client-server communication

### Authorization

```bash
# Example nginx config
location /api/v1/ebpf/ {
    auth_basic "eBPF Server";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://localhost:8527;
}
```

### Network Security

- Run server on localhost only (default)
- Use SSH tunneling for remote access
- Deploy in isolated network segment
- Use firewall rules to restrict access

## Troubleshooting

### Server Won't Start

```
Error: Address already in use
```
**Solution:**
```bash
# Check what's using port 8527
sudo lsof -i :8527

# Use different port
ecli-server --port 9000
```

### Connection Refused

```
Error: Connection refused (os error 111)
```
**Solution:**
- Ensure server is running: `ps aux | grep ecli-server`
- Check firewall: `sudo iptables -L`
- Verify endpoint URL

### Permission Denied (Native)

```
Error: Permission denied loading BPF program
```
**Solution:**
```bash
# Run with sudo
sudo ecli run program.json

# Or add capabilities
sudo setcap cap_bpf,cap_perfmon+ep $(which ecli)
```

### OCI Pull Failed

```
Error: Failed to pull from registry
```
**Solution:**
```bash
# Login first
ecli login ghcr.io

# Check image name
ecli pull ghcr.io/org/tool:latest  # Include tag
```

## Performance

### Benchmarks

- **Native execution**: <100ms startup overhead
- **Remote execution**: ~50ms network latency (local network)
- **Log streaming**: 10K+ logs/sec throughput
- **OCI pull**: ~2-5s for typical packages (depends on network)

### Optimization Tips

1. **Use native mode** for local development (lower latency)
2. **Batch log requests** instead of frequent polling
3. **Set appropriate log buffer size** on server
4. **Use OCI for distribution** (better caching than URLs)

## Examples

### Complete Workflow

```bash
# 1. Compile program
ecc program.bpf.c -o dist/

# 2. Test locally
sudo ecli run dist/package.json

# 3. Push to registry
ecli push dist/package.json ghcr.io/myorg/tool:v1.0

# 4. Deploy remotely
ecli client --endpoint http://prod-server:8527 \
  start ghcr.io/myorg/tool:v1.0

# 5. Monitor logs
ecli client --endpoint http://prod-server:8527 \
  log 1 --follow
```

### Multi-Server Deployment

```bash
# Deploy to multiple servers
for server in server1 server2 server3; do
  ecli client --endpoint http://$server:8527 \
    start ghcr.io/myorg/tool:v1.0
done

# Collect logs from all
for server in server1 server2 server3; do
  ecli client --endpoint http://$server:8527 log 1 > $server.log &
done
wait
```

## Development

### Running Tests

```bash
# Unit tests
cargo test -p ecli-lib

# Integration tests
cargo test -p ecli --test integration

# With logging
RUST_LOG=debug cargo test
```

### Code Generation

```bash
# Regenerate API code from apis.yaml
cd server-codegen
./regenerate.sh
```

### Adding New Endpoints

1. Update `apis.yaml`
2. Regenerate code: `./regenerate.sh`
3. Implement handler in `ecli-lib/src/runner/server_http/`
4. Add client method in `ecli-lib/src/runner/client/`

## Resources

- [API Specification](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/ecli/apis.yaml) - OpenAPI schema
- [eunomia-bpf Runtime](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/bpf-loader-rs) - Core library
- [Compiler](https://github.com/eunomia-bpf/eunomia-bpf/tree/master/compiler) - ecc toolchain

## License

MIT LICENSE - See [LICENSE](https://github.com/eunomia-bpf/eunomia-bpf/blob/master/LICENSE)
