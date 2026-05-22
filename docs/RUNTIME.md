# Runtime (`ruso-runtime`)

The runtime executes `BytecodeProgram` without parsing `.ruso` source. Integrators embed `Executor` directly; the CLI is optional.

## Entry points

```rust
use ruso_runtime::{Executor, ExecutorConfig, BytecodeProgram};

// From compiler
let executor = Executor::from_bytecode(config, program)?;

// From bytes (RUSO v2)
let executor = Executor::from_bytes(config, &bytes)?;

let result = executor.run().await?;
```

`ExecutionResult`:

| Field | Meaning |
|-------|---------|
| `success` | No `fail` instruction |
| `detected` | A finding was produced |
| `report` | Findings + metadata |
| `variables` | Final variable map |
| `metadata` | Check metadata from spec |

## Port reachability cache

Before the VM runs, `Executor::run` probes every TCP port required by socket probes in the program spec (`tcp`, `udp`, wire-mode `dns`). Results live in a process-wide cache for **30 seconds** (`PortCache::global()`).

If any required port is closed (live probe or cache hit), **only that script run** is skipped:

- `ExecutionResult.skipped = true`
- `ExecutionResult.skip_reason` — e.g. `port example.com:443 closed`
- `ExecutionResult.port_checks` — per-endpoint open/closed snapshot

Other scripts in the same `ruso scan` continue. Scripts that share the same closed `host:port` within 30s are skipped without reconnecting. Endpoints come from socket probes and from `--target` (`https://host` → port 443) when the check uses HTTP.

## ExecutorConfig

| Field | Default | Role |
|-------|---------|------|
| `base_url` | `""` | HTTP probe base (from CLI `--target`) |
| `default_timeout` | 30s | Connect/read fallback |
| `follow_redirect` | true | HTTP client |
| `verify_ssl` | false | HTTP **and** TCP TLS (`tls true`); scanner default skips cert verify |
| `proxy` | none | HTTP proxy URL |

CLI `--verify-tls` sets `verify_ssl = true` for the whole run. Per HTTP probe, `verify_ssl true|false` in the script overrides the global default for that request only.

## send_probe flow

1. Resolve probe name in `program.spec.probes`.  
2. `interpolate_socket_spec` — substitute `{{ var }}` in host/payload when payload is valid UTF-8.  
3. Dispatch by `ProbeKind`:

### HTTP

`execute_http` builds a reqwest request from `HttpRequestSpec` + `base_url`, returns `ProbeResponse::Http`. TLS verify follows `HttpRequestSpec.verify_ssl` when set, otherwise `ExecutorConfig.verify_ssl`.

### DNS

- **Resolver mode** (`port` and `payload` both absent): `resolve_host` → `ProbeResponse::DnsResolve`.  
- **Wire mode**: `run_dns_probe` → UDP exchange → `ProbeResponse::Socket`.

### TCP

Requires `port`. Uses `exchange_tcp_probe`:

| `session` | Behavior |
|-----------|----------|
| `false` | Connect, optional TLS, one exchange, close |
| `true` | Reuse `ProbeSession::Tcp` in `context.sessions`; append response data |

### UDP

Requires `port`. `tls` is rejected. Session reuse mirrors TCP with `ProbeSession::Udp`.

### Send payload override

`Instr::Send { payload: Some(id) }` uses `program.payloads[id]` instead of spec payload for that invocation only.

## Session and TLS (`runtime/session.rs`)

**TCP plain**

`TcpStream::connect` → optional write → read loop.

**TCP TLS**

`tokio-rustls` with WebPKI roots when `verify_ssl` is true; custom `NoVerifier` when false (default).

**Multi-read (`read_idle_ms > 0`)**

After each read chunk, wait up to `read_idle_ms` for more data; stop on idle timeout or `read_max` bytes.

**Single read (`read_idle_ms == 0`)**

One read up to `read_max` (buffer chunk 4096), subject to I/O timeout (3s per operation by default).

## Response types

```rust
pub enum ProbeResponse {
    Http(HttpResponse),
    DnsResolve(DnsResolveResponse),
    Socket(SocketResponse),
}
```

Socket `data` is `String` from UTF-8 lossy conversion of bytes—fine for text protocols; binary matching uses regex on lossy string or future byte matchers.

## Matcher evaluation

`runtime/matcher.rs` evaluates `QualifiedMatch` against stored responses:

- HTTP → status, body, headers, timing, size  
- DnsResolve → `answer` (joined A/AAAA strings)  
- Socket → `response` / `banner` on `data`  

Failed match sets `context.matched = false` (AND chain).

## Context lifecycle

```rust
pub struct Context {
    pub variables: HashMap<String, String>,
    pub responses: HashMap<String, ProbeResponse>,
    pub sessions: HashMap<String, ProbeSession>,
    pub loop_stack: Vec<LoopFrame>,
    pub matched: bool,
    pub evidence: Vec<String>,
    // …
}
```

At end of `run_bytecode`: `close_sessions()` drops open sockets, then `finalize_finding()`.

## Errors

`RuntimeError` includes unknown probe, wrong probe kind for field, bytecode decode errors, flow `fail`, I/O timeouts, etc. The CLI maps these to exit codes and stderr.

## Dependencies

| Crate | Use |
|-------|-----|
| `tokio` | Async runtime, sockets |
| `reqwest` | HTTP |
| `tokio-rustls` / `rustls` | TCP TLS |
| `regex` | Matchers and extract |
| `tracing` | Instrumentation (`RUST_LOG`) |

## Testing runtime changes

1. Unit tests in `runtime/*` modules (`#[cfg(test)]`).  
2. Compile a `.ruso` script and `Executor::from_bytecode` + manual run.  
3. `format_human` / round-trip `encode` → `decode` for bytecode changes.

Always bump `VERSION` when changing wire layout.
