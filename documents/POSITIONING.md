# eunomia-bpf Positioning Strategy & Competitive Analysis

**Last Updated:** October 2025
**Purpose:** Strategic guidance for positioning eunomia-bpf in the eBPF ecosystem

---

## Executive Summary

eunomia-bpf occupies a **unique position** in the eBPF ecosystem as the only active, comprehensive distribution platform that combines CO-RE portability, OCI packaging, WebAssembly integration, and zero-boilerplate development. While similar projects exist (notably BumbleBee), none offer the same breadth of capabilities or active development momentum.

**Key Insight:** The market has development frameworks (BCC, libbpf) and end-user tools (Cilium, Falco), but lacks a **distribution platform** for eBPF tool builders. eunomia-bpf fills this critical gap.

---

## Current State Analysis

### Existing Positioning (README.md)

**Current tagline:**
> "simplify and enhance eBPF with CO-RE and WebAssembly"

**Current description:**
> "A compiler and runtime framework to help you build and distribute eBPF program easier."

### Problems with Current Positioning

1. **Too Generic:** "Simplify and enhance" applies to most eBPF tools
2. **Buried Lead:** Distribution capabilities are understated
3. **Feature List Confusion:** Mixes writing, building, and distributing without clear hierarchy
4. **No Differentiation:** Doesn't explain why choose eunomia-bpf over alternatives
5. **Missing "Aha Moment":** The URL-execution demo is powerful but not emphasized enough

---

## Competitive Landscape

### Direct Competitors

#### 1. BumbleBee (Solo.io)

**Status:** Announced 2022, appears to have stalled (limited recent activity)

**Similarities:**
- OCI image packaging for eBPF programs
- Auto-generation of userspace code
- Docker-like CLI experience (`bee` vs `ecli`)
- Focus on distribution

**eunomia-bpf Advantages:**
- ✅ Active development (v1.0 released, 2025 updates)
- ✅ WebAssembly integration (BumbleBee has none)
- ✅ Multiple distribution formats (JSON, OCI, Wasm)
- ✅ URL-based execution without pull
- ✅ Client-server architecture
- ✅ Comprehensive tutorial ecosystem
- ✅ Proven in production

**Positioning Against BumbleBee:**
> "BumbleBee promised the vision. eunomia-bpf delivers it—with active development, WebAssembly support, and a thriving ecosystem."

---

#### 2. bpfman/bpfd (Red Hat/CNCF Sandbox)

**Focus:** Kubernetes-native eBPF deployment and lifecycle management

**Similarities:**
- OCI image support for eBPF programs
- Lifecycle management
- System-level eBPF coordination

**eunomia-bpf Advantages:**
- ✅ Developer-focused (build + distribute), not just deploy
- ✅ Works outside Kubernetes
- ✅ Compiler toolchain included
- ✅ Zero-boilerplate development
- ✅ WebAssembly programmability

**Positioning Against bpfman:**
> "bpfman deploys eBPF programs in Kubernetes. eunomia-bpf helps you build those programs and distribute them everywhere."

**Complementary Relationship:** eunomia-bpf packages could be deployed via bpfman

---

### Framework Competitors

#### 3. BCC (BPF Compiler Collection)

**Focus:** Python/C++ framework for eBPF development

**Limitations:**
- ❌ No CO-RE support (requires kernel headers)
- ❌ Runtime compilation (heavy dependencies)
- ❌ Large binary size
- ❌ No distribution mechanism
- ❌ Deprecated in favor of libbpf

**eunomia-bpf Advantages:**
- ✅ CO-RE portability
- ✅ Compile once, run everywhere
- ✅ Lightweight runtime
- ✅ Built-in distribution
- ✅ Modern toolchain

**Positioning Against BCC:**
> "BCC pioneered eBPF development. eunomia-bpf brings it to the cloud-native era with CO-RE, containers, and WebAssembly."

---

#### 4. libbpf + libbpf-bootstrap

**Focus:** Low-level library and project scaffolding

**What They Provide:**
- Core eBPF loading primitives
- BPF skeleton generation
- Project templates

**What They Don't Provide:**
- ❌ Automatic userspace code generation
- ❌ CLI argument parsing
- ❌ Data export handling (ring buffer, maps)
- ❌ Packaging/distribution
- ❌ Deployment tooling

**eunomia-bpf Advantages:**
- ✅ Built on libbpf (compatible)
- ✅ Eliminates all userspace boilerplate
- ✅ Complete toolchain (compile, package, distribute, run)
- ✅ JSON metadata system
- ✅ Multiple distribution formats

**Positioning Against libbpf:**
> "libbpf is the foundation. eunomia-bpf is the complete building—write kernel code only, we generate everything else."

---

### End-User Tool Competitors

#### 5. Cilium / Tetragon

**Focus:** Specific use cases (networking, security observability)

**Not Direct Competitors Because:**
- End-user tools, not development platforms
- Solve specific problems, not general-purpose
- Users consume, don't build

**Relationship:** eunomia-bpf helps build tools like Cilium/Tetragon

---

#### 6. Falco

**Focus:** Runtime security detection

**Not Direct Competitors Because:**
- Specific security use case
- Not a development framework
- Rule-based, not programmable

**Relationship:** eunomia-bpf could distribute Falco-like tools

---

### Ecosystem Projects

#### 7. wasm-bpf

**Status:** Part of the eunomia-bpf ecosystem!

**Provides:** WebAssembly runtime for eBPF control planes

**Strategic Value:**
- Unique differentiator (no other project has this)
- Enables programmable eBPF
- Cloud-native Wasm integration
- Published research paper (academic credibility)

---

## Competitive Matrix

| Feature | BCC | libbpf | libbpf-bootstrap | BumbleBee | bpfman | **eunomia-bpf** |
|---------|-----|--------|------------------|-----------|--------|-----------------|
| **CO-RE Support** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Auto Userspace** | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| **JSON Packaging** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **OCI Distribution** | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **URL Execution** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Wasm Integration** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Compiler Toolchain** | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| **Runtime/Loader** | ✅ | ✅ | Template | ✅ | ✅ | ✅ |
| **K8s Native** | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| **Active Development** | ⚠️ | ✅ | ✅ | ⚠️ | ✅ | ✅ |
| **Tutorial Ecosystem** | ✅ | ⚠️ | ⚠️ | ❌ | ⚠️ | ✅ |

**Legend:** ✅ Yes | ❌ No | ⚠️ Limited/Partial

---

## Market Gaps & Opportunities

### 1. Distribution Platform Gap ⭐⭐⭐

**The Problem:**
No mature, general-purpose platform for packaging and distributing eBPF programs exists.

**Current State:**
- BumbleBee promised this but appears stalled
- bpfman focuses on K8s deployment, not packaging
- Most tools are monolithic (Cilium, Falco)

**eunomia-bpf Solution:**
- Active, production-ready distribution platform
- Multiple formats (JSON, OCI, Wasm)
- Registry-agnostic (works with Docker Hub, ghcr.io, etc.)

**Positioning:**
> "The first and only active distribution platform for eBPF tools"

---

### 2. Zero-Boilerplate Development ⭐⭐

**The Problem:**
Writing eBPF tools requires extensive userspace code (ring buffer handling, CLI parsing, metrics, etc.)

**Current State:**
- libbpf-bootstrap provides templates, but you still write the code
- BumbleBee promised auto-generation, but limited adoption

**eunomia-bpf Solution:**
- Automatic CLI argument generation from kernel code
- Auto-export via ring buffer, perf events, or map sampling
- Histogram generation for hash maps
- Complete userspace handling

**Positioning:**
> "Write kernel code only. Zero userspace boilerplate."

---

### 3. WebAssembly Integration ⭐⭐⭐

**The Problem:**
eBPF control planes are typically written in native code, limiting portability and programmability.

**Current State:**
- NO other eBPF framework integrates WebAssembly comprehensively
- Wasm + eBPF research is emerging but not productized

**eunomia-bpf Solution:**
- wasm-bpf: Full Wasm runtime for eBPF programs
- Write control planes in C/C++, Rust, Go (compile to Wasm)
- Portable, sandboxed, cloud-native
- Published research (academic validation)

**Positioning:**
> "The only eBPF platform with production-ready WebAssembly integration"

**Strategic Importance:** This is the **strongest differentiator** and should be emphasized heavily.

---

### 4. URL-Based Execution ⭐⭐

**The Problem:**
Running eBPF tools requires download, compilation, or installation.

**Current State:**
- Traditional tools: git clone, compile, install
- OCI-based tools: docker pull, extract, run

**eunomia-bpf Solution:**
```bash
sudo ecli run https://example.com/package.json
```

**No other tool offers this:**
- No pull required (streams from URL)
- No installation
- Instant execution

**Positioning:**
> "curl for eBPF: Run programs from URLs with one command"

---

### 5. Multi-Format Flexibility ⭐

**The Problem:**
Developers need different distribution formats for different use cases.

**Current State:**
- Most tools lock you into one format
- OCI is heavy for simple scripts
- No lightweight option exists

**eunomia-bpf Solution:**
- **JSON:** Lightweight, simple, self-contained
- **OCI:** Cloud-native, registry-compatible
- **Wasm:** Programmable, portable, sandboxed

**Positioning:**
> "Distribute your way: lightweight JSON, cloud-native OCI, or programmable Wasm"

---

## Unique Value Propositions (Prioritized)

### Tier 1: Market-Defining Capabilities

1. **WebAssembly + eBPF Integration**
   - Only production-ready solution
   - Published research backing
   - Future-proof architecture
   - **Tag:** "Programmable eBPF"

2. **Complete Distribution Platform**
   - Build + Package + Distribute + Run
   - Only active, comprehensive solution
   - **Tag:** "The npm for eBPF"

3. **URL-Based Execution**
   - Genuinely unique capability
   - Powerful demo/hook
   - **Tag:** "curl for eBPF"

### Tier 2: Strong Differentiators

4. **Zero Userspace Boilerplate**
   - Write kernel code only
   - Auto-generate everything else
   - **Tag:** "Kernel code only"

5. **Multi-Format Distribution**
   - JSON + OCI + Wasm flexibility
   - Choose your workflow
   - **Tag:** "Your choice of format"

### Tier 3: Table Stakes

6. **CO-RE Portability**
   - Standard now, but essential
   - **Tag:** "Compile once, run everywhere"

7. **Client-Server Architecture**
   - Remote management
   - Less unique, but useful
   - **Tag:** "eBPF as a service"

---

## Recommended Positioning Statements

### Primary (Developer Audience)

**Tagline:**
> "The distribution platform for eBPF tools"

**One-Liner:**
> "Build, package, and share eBPF programs like containers. Write kernel code, run from URLs, distribute as OCI images."

**Elevator Pitch:**
> "eunomia-bpf is a compiler, runtime, and distribution platform that lets you write eBPF programs using only kernel code, package them as JSON or OCI images, and run them from URLs or registries. With WebAssembly integration, you can build programmable, portable observability and security tools faster than any other framework."

---

### Secondary (Technical Audience)

**Tagline:**
> "CO-RE compiler + OCI packaging + WebAssembly runtime for portable eBPF"

**One-Liner:**
> "A complete toolchain for building CO-RE eBPF programs, automatically generating userspace code, and distributing via JSON, OCI, or WebAssembly."

**Elevator Pitch:**
> "eunomia-bpf combines a CO-RE-aware compiler (ecc), a dynamic loading runtime (bpf-loader), and a CLI tool (ecli) to eliminate userspace boilerplate, enable kernel-version-agnostic deployment, and support distribution via OCI registries or simple URLs. The integrated wasm-bpf runtime allows control planes in any Wasm-compatible language."

---

### Tertiary (Business Audience)

**Tagline:**
> "Make eBPF tools as easy to share as Docker containers"

**One-Liner:**
> "The first platform for building and distributing portable eBPF observability and security tools across any Linux environment."

**Elevator Pitch:**
> "eBPF is powerful but hard to distribute. eunomia-bpf solves this by providing a complete toolchain that turns eBPF source code into shareable, portable packages. Tool builders write only kernel code—we handle compilation, packaging, and distribution. Users run tools with a single command from URLs or OCI registries, no compilation required."

---

## Positioning Against Specific Competitors

### vs. BumbleBee (Most Similar)

**Differences:**
- ✅ Active development (BumbleBee stalled since ~2023)
- ✅ WebAssembly support (BumbleBee has none)
- ✅ URL execution without pull
- ✅ JSON format option (lighter weight)
- ✅ Proven ecosystem and tutorials

**Messaging:**
> "BumbleBee showed the promise of OCI-packaged eBPF. eunomia-bpf delivers on that promise with active development, WebAssembly integration, and a complete ecosystem."

**When to Use:**
When someone asks "How is this different from BumbleBee?" or "Is BumbleBee still active?"

---

### vs. libbpf + libbpf-bootstrap (Most Common Alternative)

**Differences:**
- ✅ Zero userspace boilerplate (they require manual code)
- ✅ Distribution built-in (they provide none)
- ✅ Packaging formats (they stop at .o files)
- ⚠️ Both use libbpf underneath (compatible)

**Messaging:**
> "libbpf-bootstrap gives you a skeleton. eunomia-bpf gives you a complete, distributable tool. Write kernel code, and we'll generate the CLI, data export, and packaging automatically."

**When to Use:**
When someone is starting a new eBPF project and evaluating frameworks

---

### vs. bpfman (Enterprise/K8s Audience)

**Differences:**
- ✅ Includes build toolchain (bpfman is deploy-only)
- ✅ Works outside Kubernetes
- ✅ Developer-focused, not just ops
- ⚠️ bpfman has stronger K8s integration

**Messaging:**
> "bpfman deploys and manages eBPF programs in Kubernetes. eunomia-bpf helps you build those programs and distribute them everywhere—Kubernetes, bare metal, or edge devices."

**Complementary Story:**
> "Build with eunomia-bpf, deploy with bpfman"

**When to Use:**
When talking to K8s/platform engineering teams

---

### vs. BCC (Legacy Migration)

**Differences:**
- ✅ CO-RE portability (BCC requires kernel headers)
- ✅ Smaller binaries (no runtime compilation)
- ✅ Distribution support (BCC has none)
- ✅ Modern toolchain

**Messaging:**
> "BCC revolutionized eBPF development but predates CO-RE and cloud-native distribution. eunomia-bpf brings BCC's ease of use to the modern era—portable, lightweight, and cloud-ready."

**When to Use:**
When talking to teams with existing BCC tools looking to modernize

---

## Target Audiences & Use Cases

### Primary Audience: eBPF Tool Builders

**Who:**
- Developers building observability tools
- Security researchers creating detection tools
- Performance engineers writing profilers
- SREs automating kernel diagnostics

**Pain Points:**
- Too much userspace boilerplate
- Hard to distribute tools to others
- Kernel version compatibility nightmares
- No good packaging standard

**Value Proposition:**
> "Build production-ready eBPF tools in hours, not weeks. Write kernel code, and we'll handle the rest—packaging, distribution, and runtime."

**Key Features:**
1. Zero userspace boilerplate
2. Automatic CLI generation
3. OCI/JSON packaging
4. CO-RE portability

---

### Secondary Audience: Platform Engineers

**Who:**
- DevOps/SRE teams deploying observability
- Security teams rolling out detection tools
- Cloud platform builders

**Pain Points:**
- Hard to deploy eBPF across heterogeneous environments
- Kernel version fragmentation
- Difficult to manage multiple eBPF programs
- Need remote/centralized control

**Value Proposition:**
> "Deploy portable eBPF tools across any Linux environment. CO-RE means no kernel-specific compilation. OCI means use your existing registries and workflows."

**Key Features:**
1. CO-RE portability
2. OCI distribution
3. Client-server management
4. URL-based deployment

---

### Tertiary Audience: Wasm/Cloud-Native Developers

**Who:**
- Wasm ecosystem developers
- Cloud-native application builders
- Edge computing platforms

**Pain Points:**
- Want kernel access from Wasm
- Need portable, sandboxed observability
- Seeking next-gen cloud-native architectures

**Value Proposition:**
> "The only platform bringing eBPF to WebAssembly. Write control planes in any Wasm language, access kernel data safely, and deploy anywhere."

**Key Features:**
1. wasm-bpf runtime
2. Multi-language support (C/C++, Rust, Go)
3. Wasm sandboxing
4. Cloud-native architecture

---

## Recommended README Structure

### Opening (Hook)

```markdown
# eunomia-bpf: The Distribution Platform for eBPF Tools

> Build, package, and share eBPF programs like containers.
> Write kernel code, run from URLs, distribute as OCI images.

[![Demo](demo.gif)](https://eunomia.dev/demos)

**Run a production eBPF tool in one command:**
```bash
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ecli
sudo ./ecli run https://eunomia-bpf.github.io/.../sigsnoop/package.json
```

No compilation. No installation. Just eBPF.
```

---

### Problem Statement

```markdown
## The Problem with eBPF Today

Building eBPF tools is hard:
- ❌ **Boilerplate Hell:** Ring buffers, CLI parsing, metrics—hundreds of lines before your first trace
- ❌ **Distribution Desert:** No standard way to package or share eBPF programs
- ❌ **Portability Pain:** Different kernels need different binaries (or worse, runtime compilation)
- ❌ **Deployment Difficulty:** Users clone repos, install dependencies, cross fingers

**What if you could:**
- ✅ Write only kernel code and get a complete tool
- ✅ Package eBPF programs like Docker images
- ✅ Compile once and run on any kernel version
- ✅ Let users run your tool from a URL with one command
```

---

### Solution (What is eunomia-bpf)

```markdown
## What is eunomia-bpf?

eunomia-bpf is a **complete toolchain and runtime** for building and distributing eBPF programs:

**🔨 ecc** - Compiler that turns eBPF C code into portable packages
**📦 JSON/OCI Packaging** - Distribute via registries or simple files
**🚀 ecli** - Runtime that loads and runs eBPF programs from anywhere
**🌐 wasm-bpf** - WebAssembly integration for programmable control planes

### Write Kernel Code Only

```c
// sigsnoop.bpf.c - complete eBPF program
SEC("tracepoint/signal/signal_generate")
int sig_trace(struct trace_event_raw_signal_generate *ctx) {
    struct event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.sig = ctx->sig;
    bpf_ringbuf_output(&rb, &event, sizeof(event), 0);
    return 0;
}
```

**That's it.** No userspace code. eunomia-bpf auto-generates:
- Ring buffer handling
- CLI argument parsing
- Event formatting and output
- Complete working tool

### Compile Once, Run Everywhere

```bash
# Compile with CO-RE support
./ecc sigsnoop.bpf.c

# Run on any kernel (4.x, 5.x, 6.x+)
sudo ./ecli run sigsnoop.json
```

### Distribute Like Containers

```bash
# Push to any OCI registry
./ecli push sigsnoop.json ghcr.io/yourorg/sigsnoop:latest

# Users run directly
sudo ./ecli run ghcr.io/yourorg/sigsnoop:latest
```

### Or Just Use a URL

```bash
# No download, no pull, just run
sudo ./ecli run https://example.com/sigsnoop.json
```
```

---

### Differentiation Section

```markdown
## Why eunomia-bpf?

### vs. BCC / libbpf
- **Zero boilerplate:** Write kernel code only, we generate the rest
- **Portable binaries:** CO-RE means compile once, run everywhere
- **Built-in distribution:** Package and share tools easily

### vs. BumbleBee
- **Active development:** Regular updates and v1.0 release
- **WebAssembly integration:** Programmable control planes (unique!)
- **Multiple formats:** JSON, OCI, and Wasm distribution
- **Proven ecosystem:** Tutorials, examples, production usage

### vs. bpfman
- **Complete toolchain:** Build + package + distribute + deploy
- **Works everywhere:** Not just Kubernetes
- **Developer-focused:** For tool builders, not just operators

### The Only Platform With:
- ✅ WebAssembly + eBPF integration
- ✅ URL-based execution
- ✅ Auto-generated userspace code
- ✅ JSON + OCI + Wasm distribution
- ✅ Active development + ecosystem
```

---

### Feature Matrix

```markdown
## Feature Comparison

| Feature | BCC | libbpf | BumbleBee | bpfman | **eunomia-bpf** |
|---------|-----|--------|-----------|--------|-----------------|
| CO-RE Portability | ❌ | ✅ | ✅ | ✅ | ✅ |
| Auto Userspace | ❌ | ❌ | ✅ | ❌ | ✅ |
| OCI Distribution | ❌ | ❌ | ✅ | ✅ | ✅ |
| URL Execution | ❌ | ❌ | ❌ | ❌ | ✅ |
| Wasm Integration | ❌ | ❌ | ❌ | ❌ | ✅ |
| Compiler Toolchain | ✅ | ❌ | ✅ | ❌ | ✅ |
| Active Development | ⚠️ | ✅ | ⚠️ | ✅ | ✅ |
```

---

### Use Cases

```markdown
## Use Cases

### 🔍 Observability Tool Builders
Build the next `tcpdump` or `perf` tool:
```bash
# Write kernel tracing code
# Auto-generate CLI: --pid, --duration, --output
# Package as OCI image
# Users install with: ecli run ghcr.io/yourorg/tool
```

### 🔒 Security Researchers
Distribute detection tools instantly:
```bash
# Create runtime security detector
# Compile once with CO-RE
# Share via URL: ecli run https://research.org/detector.json
# Works on any kernel version
```

### 🚀 Platform Engineers
Deploy observability across fleets:
```bash
# Central server manages eBPF programs
# Push to OCI registry
# Pull and run on thousands of nodes
# CO-RE ensures compatibility
```

### 🌐 Wasm Developers
Build cloud-native kernel tools:
```bash
# Write control plane in Rust
# Compile to Wasm
# Access kernel via eBPF
# Deploy anywhere with wasm-bpf runtime
```
```

---

## Messaging Framework

### Key Messages (Prioritized)

#### Message 1: Distribution Platform
**Headline:** "The npm for eBPF tools"
**Support:** "The first and only active platform for packaging and distributing eBPF programs via OCI images, JSON files, or WebAssembly modules."
**Proof Points:**
- OCI registry integration (ghcr.io, Docker Hub)
- URL-based execution
- Multiple format support
- Active ecosystem (tutorials, examples)

---

#### Message 2: WebAssembly Integration
**Headline:** "The only eBPF platform with production-ready WebAssembly"
**Support:** "wasm-bpf enables programmable eBPF control planes in any Wasm language—C/C++, Rust, Go—with sandboxing, portability, and cloud-native architecture."
**Proof Points:**
- Published research paper
- Working runtime implementation
- Multi-language support
- No other platform offers this

---

#### Message 3: Zero Boilerplate
**Headline:** "Write kernel code only"
**Support:** "eunomia-bpf auto-generates all userspace code—CLI parsing, ring buffer handling, event formatting, and metrics—from your eBPF kernel code."
**Proof Points:**
- Automatic CLI generation
- Auto-export mechanisms
- Histogram generation
- Complete working tools from kernel code alone

---

#### Message 4: URL Execution
**Headline:** "curl for eBPF"
**Support:** "Run eBPF programs directly from URLs with a single command. No download, no compilation, no installation."
**Proof Points:**
- `ecli run https://...` demo
- No other tool offers this
- Instant execution
- Zero prerequisites

---

#### Message 5: CO-RE Portability
**Headline:** "Compile once, run everywhere"
**Support:** "CO-RE support means your eBPF programs work across kernel versions without recompilation—4.x, 5.x, 6.x, and beyond."
**Proof Points:**
- BTF-based relocations
- Kernel-agnostic binaries
- No kernel headers needed
- Production-proven

---

### Message Sequencing

**For Developers (Build Focus):**
1. Zero boilerplate → Developer productivity
2. CO-RE portability → No compatibility hassles
3. Distribution platform → Easy sharing
4. Wasm integration → Advanced capabilities

**For Operators (Deploy Focus):**
1. Distribution platform → Easy deployment
2. CO-RE portability → Works everywhere
3. URL execution → Simple operations
4. OCI integration → Familiar workflows

**For Decision Makers (Strategic Focus):**
1. Distribution platform → Market gap
2. Wasm integration → Future-proof
3. Active ecosystem → Lower risk
4. CO-RE portability → Cost savings

---

## Content Strategy

### Homepage / README

**Structure:**
1. **Hero:** Problem → Solution → Demo (30 seconds to "aha moment")
2. **Value Props:** 3-4 key benefits with proof
3. **Differentiation:** Comparison table
4. **Use Cases:** 3-4 personas with examples
5. **Getting Started:** Quick start in <5 minutes
6. **Ecosystem:** Tutorials, examples, community

**Tone:** Direct, technical, confident but not arrogant

---

### Documentation

**Add/Update:**
1. **"Why eunomia-bpf?"** page comparing to alternatives
2. **Migration guides:** From BCC, libbpf-bootstrap, BumbleBee
3. **Use case tutorials:** By persona (builder, operator, researcher)
4. **Wasm integration guide:** Emphasize uniqueness
5. **Distribution guide:** JSON vs OCI vs Wasm decision tree

---

### Blog / Announcements

**Recommended Posts:**
1. "Introducing eunomia-bpf: The Distribution Platform for eBPF"
2. "Why We Built WebAssembly Support for eBPF (And Why It Matters)"
3. "Migrating from BCC to eunomia-bpf: A Case Study"
4. "Behind the Scenes: How URL Execution Works"
5. "eunomia-bpf vs BumbleBee: A Technical Comparison"

---

### Conference Talks

**Titles:**
- "Building the npm for eBPF: Lessons Learned"
- "WebAssembly + eBPF: Programmable Kernel Observability"
- "CO-RE and Beyond: Making eBPF Tools Portable"
- "From Kernel Code to OCI Image in 60 Seconds"

**Demo Flow:**
1. Write simple eBPF program (30s)
2. Compile with ecc (15s)
3. Run locally (15s)
4. Push to OCI registry (30s)
5. Run from URL on different machine (30s)
6. Show Wasm integration (60s)

---

## FAQ / Objections Handling

### "How is this different from BumbleBee?"

**Answer:**
"BumbleBee was announced in 2022 with a similar vision but appears to have stalled. eunomia-bpf is actively developed with v1.0 released, WebAssembly integration, URL-based execution, and a proven ecosystem with tutorials and production usage."

---

### "Why not just use libbpf?"

**Answer:**
"libbpf is excellent and we build on top of it. But libbpf is a library—you still need to write userspace code for CLI parsing, data handling, etc. eunomia-bpf auto-generates all that, letting you write only kernel code."

---

### "Do I need to learn WebAssembly?"

**Answer:**
"No. WebAssembly support is optional for advanced use cases. Most users will use JSON or OCI packaging. Wasm is there when you need programmable control planes or want to run eBPF programs in Wasm runtimes."

---

### "Does this work with Kubernetes?"

**Answer:**
"Yes. You can package programs as OCI images and deploy them however you like—including with bpfman for Kubernetes-native management. eunomia-bpf focuses on building and packaging; it complements K8s deployment tools."

---

### "Is this production-ready?"

**Answer:**
"Yes. eunomia-bpf v1.0 was released after extensive testing. It's built on battle-tested libbpf, supports CO-RE for portability, and includes comprehensive examples and tutorials. The wasm-bpf component has published research backing it."

---

### "What's the performance overhead?"

**Answer:**
"Minimal. The eBPF programs run natively in the kernel with standard libbpf overhead. The JSON packaging adds negligible load-time parsing. Wasm control planes have <5% overhead compared to native, per our research."

---

### "Can I migrate from existing BCC tools?"

**Answer:**
"Yes. While you'll need to rewrite using libbpf style (which eunomia-bpf supports), the kernel code logic stays similar. We have migration guides and examples. The payoff is CO-RE portability and zero userspace boilerplate."

---

## Metrics & Success Indicators

### Awareness Metrics
- GitHub stars growth rate
- Website traffic to /docs
- Conference talk attendance
- Social media mentions

### Adoption Metrics
- `ecli` download count
- GitHub issues/questions
- OCI image pulls from registry
- Tutorial completion rates

### Engagement Metrics
- Community contributions
- Example program submissions
- Blog post engagement
- Discord/community activity

### Differentiation Metrics
- "eunomia-bpf vs X" search volume
- Comparison page views
- Migration guide usage
- Competitive mentions

---

## Action Items

### Immediate (This Week)

1. **Update README.md:**
   - New hero section with problem/solution
   - Add comparison table
   - Emphasize Wasm differentiation
   - Add "Why eunomia-bpf?" section

2. **Create Comparison Page:**
   - vs. BumbleBee
   - vs. libbpf
   - vs. bpfman
   - Decision matrix

3. **Audit Documentation:**
   - Identify gaps in differentiation
   - Add competitive context where relevant

### Short Term (This Month)

4. **Write Blog Post:**
   - "Introducing eunomia-bpf v1.0: The Distribution Platform for eBPF"
   - Hit key messages: distribution, Wasm, zero boilerplate

5. **Create Migration Guides:**
   - From BCC
   - From libbpf-bootstrap
   - From BumbleBee

6. **Produce Demo Video:**
   - 2-minute "Kernel code to OCI image" walkthrough
   - Emphasize speed and simplicity

### Medium Term (This Quarter)

7. **Conference Submissions:**
   - Target eBPF Summit, KubeCon, Linux Plumbers
   - Focus on Wasm integration (unique angle)

8. **Academic Outreach:**
   - Leverage wasm-bpf research paper
   - Engage with systems research community

9. **Community Building:**
   - Create "Built with eunomia-bpf" showcase
   - Highlight community tools
   - Package manager for eBPF programs (registry)

### Long Term (Next 6 Months)

10. **Package Registry:**
    - "npm for eBPF" requires a central registry
    - Searchable, curated eBPF programs
    - Community contributions

11. **Enterprise Features:**
    - Based on bpfman integration
    - RBAC, audit logs for enterprise
    - Support/consulting offerings

12. **Ecosystem Growth:**
    - SDKs for other languages
    - IDE/editor integrations
    - CI/CD integrations

---

## Conclusion

eunomia-bpf occupies a **unique and defensible position** in the eBPF ecosystem:

1. **Only active, comprehensive distribution platform** (BumbleBee stalled, others don't compete)
2. **Only production WebAssembly integration** (massive differentiator)
3. **Most complete developer experience** (zero boilerplate, auto-generation)
4. **Proven and growing ecosystem** (tutorials, examples, community)

**The opportunity:** Position as **the** way to build and distribute eBPF tools—like npm for Node.js, pip for Python, or cargo for Rust.

**The strategy:** Lead with distribution story, emphasize Wasm uniqueness, prove developer productivity, build the ecosystem.

**The challenge:** Awareness. Many don't know distribution is a solved problem for eBPF. Educate the market.

**The moat:** WebAssembly integration is hard to replicate. Active ecosystem creates network effects. First-mover advantage in the distribution space.

---

## References

### Research
- [BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
- [wasm-bpf Research Paper](https://arxiv.org/abs/2408.04856)
- [eBPF Ecosystem Progress 2024-2025](https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/)

### Competitors
- [BumbleBee Announcement](https://www.solo.io/blog/solo-announces-bumblebee/)
- [bpfman/bpfd GitHub](https://github.com/bpfman/bpfman)
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
- [Cilium Tetragon](https://tetragon.io/)

### Ecosystem
- [eBPF Applications Landscape](https://ebpf.io/applications/)
- [eBPF Infrastructure Landscape](https://ebpf.io/infrastructure/)

---

**Document Owner:** Project Maintainers
**Last Review:** October 2025
**Next Review:** January 2026
