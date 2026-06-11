# Architecture

Ruso splits **language** (script + compiler) from **execution** (runtime VM). The CLI is a thin driver. This keeps the bytecode contract stable while RSL evolves.

## End-to-end flow

```mermaid
flowchart LR
  subgraph script_crate [ruso-script]
    SRC[".rsl source"]
    PEST[Pest parser]
    AST[AST]
    SPEC[ProgramSpec]
    BC[BytecodeProgram]
    SRC --> PEST --> AST
    AST --> SPEC
    AST --> BC
  end
  subgraph runtime_crate [ruso-runtime]
    ENC[encode binary]
    EXEC[Executor]
    NET[HTTP / DNS / TCP / UDP]
    BC --> EXEC
    EXEC --> NET
    BC --> ENC
  end
  CLI[ruso-cli] --> SRC
  CLI --> EXEC
```

1. **Parse** — `grammar.pest` → `Program { statements }`.
2. **Build spec** — metadata + probe definitions → `ProgramSpec` (probe table only; no control flow).
3. **Compile** — executable statements → `Vec<Instr>` + string/matcher/payload pools.
4. **Execute** — `Executor` walks instructions, calls `send_probe`, evaluates matchers, emits findings.

## Why probes are not opcodes

Enterprise scanners often embed protocol logic in plugins. Ruso instead uses:

| Layer | Responsibility |
|-------|----------------|
| **Probe table** | *What* to send (HTTP path, TCP payload, DNS wire bytes, …) |
| **Instructions** | *When* to send and *how* to branch (`Send`, `Match`, `ForList`, …) |

There is a single network opcode:

```text
Send { probe_id, optional_payload_override }
```

`ProbeKind` in the probe table distinguishes HTTP vs DNS vs TCP vs UDP. Adding a Redis check does **not** add `OP_REDIS`; it adds a `tcp` probe with a RESP payload in a `.rsl` file.

Benefits:

- Scripts ship without recompiling the VM.
- Bytecode stays small and stable.
- Same executor path for all TCP-based services.

Trade-off: very complex protocol state machines still need either richer generic options (`session`, `read_idle`, loop) or future opcodes—not per-service hardcoding.

## Three crates

### `ruso-runtime`

- **Public API**: `Executor`, `ExecutorConfig`, `BytecodeProgram`, `encode_bytecode` / `decode_bytecode`, `ProgramSpec`, `SocketProbeSpec`, `RuntimeError`, `build_client`, contract types.
- **Does not parse** `.rsl` source.
- Owns all network I/O (reqwest, tokio sockets, tokio-rustls). `build_client`
  is exported so a frontend can build a preflight/probe client with the same
  TLS/proxy/redirect behaviour as the executor instead of hand-rolling one.

Key modules:

| Module | Purpose |
|--------|---------|
| `contract.rs` | Matchers, severity, HTTP method, evidence |
| `runtime/spec.rs` | `HttpRequestSpec`, `SocketProbeSpec`, `ProbeKind` |
| `runtime/bytecode.rs` | `Instr` enum |
| `runtime/binary.rs` | Wire encode/decode v1 |
| `runtime/executor.rs` | VM main loop |
| `runtime/http.rs` | HTTP client requests |
| `runtime/session.rs` | TCP/TLS connect, multi-read, UDP |
| `runtime/socket.rs` | One-shot and session exchanges |
| `runtime/dns.rs` | OS resolver vs wire UDP DNS |
| `runtime/matcher.rs` | Field predicates |
| `runtime/context.rs` | Variables, responses, sessions, loop stack |

### `ruso-script`

- **Public API**: `parse()`, `compile()`, `Program`, AST types.
- Depends on `ruso-runtime` for `ProgramSpec` and contract types.
- Pest grammar is the source of truth for syntax.

Pipeline: `parse` → `build_program_spec` → `compile`.

### `ruso-cli`

- Clap CLI: `scan`, `parse`, `compile`, `exec`.
- Wires `ExecutorConfig` (base URL, timeout, TLS verify, proxy) from flags.
- Discovers `.rsl` files and target lists for batch scans.

## Repositories (not a monorepo)

Ruso ships as **three independent Git repositories** under [Hopeless-Labs](https://github.com/Hopeless-Labs):

| Repository | Role |
|------------|------|
| [ruso-runtime](https://github.com/Hopeless-Labs/ruso-runtime) | VM, bytecode wire format, network I/O (this repo) |
| [ruso-script](https://github.com/Hopeless-Labs/ruso-script) | Pest grammar, compiler, `examples/*.rsl` |
| [ruso-cli](https://github.com/Hopeless-Labs/ruso-cli) | `ruso` binary |

A local parent folder (e.g. `Hopeless-Labs/` with sibling clones) is only for convenience on your machine. **It is not a git repository** and does not contain canonical documentation.

Dependency direction:

```text
ruso-cli → ruso-script → ruso-runtime
```

Published `Cargo.toml` files use **git dependencies** on `main` (see [Extending](EXTENDING.md)).

### Layout in this repo (`ruso-runtime`)

```text
ruso-runtime/
├── docs/              ← developer documentation
├── src/
│   ├── contract.rs    # matchers, severity, …
│   ├── opcode.rs      # opcode IDs + module docs
│   └── runtime/       # executor, http, socket, session, binary, …
└── Cargo.toml
```

Related documentation in other repos:

- RSL syntax — [ruso-script `docs/RSL_REFERENCE.md`](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/RSL_REFERENCE.md)
- Example scripts — [ruso-script `docs/EXAMPLES.md`](https://github.com/Hopeless-Labs/ruso-script/blob/main/docs/EXAMPLES.md)
- CLI — [ruso-cli `docs/CLI.md`](https://github.com/Hopeless-Labs/ruso-cli/blob/main/docs/CLI.md)

## Generic socket model

`dns`, `tcp`, and `udp` blocks all parse into the same `SocketProbe` / `SocketProbeSpec`:

```rust
pub struct SocketProbeSpec {
    pub host: String,
    pub port: Option<u16>,
    pub payload: Option<Vec<u8>>,
    pub tls: bool,
    pub session: bool,
    pub read_max: u32,
    pub read_idle_ms: u32,
}
```

Runtime behavior is selected by **probe kind** + **field values**:

| Kind | Condition | Behavior |
|------|-----------|----------|
| `Dns` | no `port`, no `payload` | OS resolver (`tokio::net::lookup_host`) → `ProbeResponse::DnsResolve` |
| `Dns` | `port` and/or `payload` | UDP to `host:port` (default 53) → `ProbeResponse::Socket` |
| `Tcp` | `port` required | TCP (+ optional TLS) exchange → `Socket` |
| `Udp` | `port` required | UDP exchange → `Socket` |

HTTP uses a separate `HttpRequestSpec` because the model is request/response document-oriented, not raw socket bytes.

## Execution state

`Context` holds per-run state:

- `variables` — `set` / `extract`
- `responses` — map probe name → `ProbeResponse`
- `sessions` — open TCP/TLS or UDP sockets when `session true`
- `loop_stack` — `ForList` / `LoopBack` / `Break`
- `matched` — AND-chain for matchers until one fails
- `evidence` — strings for the final finding

## Findings

A finding is emitted when:

1. Match chain stayed true (`context.matched`), and
2. `finalize_finding()` runs at end of bytecode (metadata name/severity, optional advisory fields including `cve` / `cwe` / `references` / `cvss` / `cvss_score` / `mitigation`, plus evidence).

Flow instructions: `stop` (halt, no finding), `exit` (halt, finalize finding), `fail` (error), `continue` (no-op), `break` (exit innermost `for`).

## What Ruso is not (yet)

- Not a scan orchestration platform (scheduling, workers, asset DB).
- Not a plugin marketplace (checks are `.rsl` files you ship).
- Not a full web crawler / Burp replacement.

It **is** a solid **check execution engine** with a small, generic bytecode ISA.
