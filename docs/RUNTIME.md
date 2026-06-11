# Runtime (`ruso-runtime`)

The runtime executes `BytecodeProgram` without parsing `.rsl` source. Integrators embed `Executor` directly; the CLI is optional.

## Entry points

```rust
use ruso_runtime::{Executor, ExecutorConfig, BytecodeProgram};

// From compiler
let executor = Executor::from_bytecode(config, program)?;

// From bytes (RUSO v1)
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
| `metadata` | Check metadata from spec (`CheckMetadata`) |

### `Finding` / `CheckMetadata`

When a check matches, `finalize_finding()` builds one `Finding` from metadata plus collected evidence:

| Field | Source |
|-------|--------|
| `name` | `name`, or `report` title if `name` omitted |
| `description`, `impact`, `author` | Optional metadata strings |
| `severity` | Metadata `severity`, default `info` |
| `cve`, `cwe`, `references`, `cvss`, `cvss_score` | Repeatable RSL lines → `Vec<String>` |
| `mitigation` | Single free-text line → `Option<String>` (declaring it twice is a compile error) |
| `evidence` | `evidence <probe>.body` or `evidence <probe> regex '…'` on that probe only |

## Port reachability cache

Before the VM runs, `Executor::run` TCP-connect-probes the ports required by **`tcp`** probes in the program spec (plus the `--target` host:port for HTTP checks). Results live in a process-wide cache for **30 seconds** (`PortCache::global()`). `udp` and wire-mode `dns` probes are connectionless — a TCP connect to their port proves nothing about the UDP service, so they are *not* pre-checked and always run, bounded only by their own read timeout.

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
| `read_timeout` | 10s | Per-read I/O timeout for socket probes |
| `max_response_bytes` | 10 MiB | HTTP body cap |
| `follow_redirect` | true | HTTP client |
| `verify_ssl` | **true** | HTTP **and** TCP TLS (`tls true`) |
| `proxy` | none | HTTP proxy URL |
| `max_script_duration` | 5 minutes | Wall-clock budget per script (`None` disables) |
| `http_retries` | 2 | Transient-transport retries per HTTP probe (`0` disables) |

`verify_ssl` defaults to **true**. Earlier revisions defaulted to `false`
("scanner mode"), which made a freshly-constructed runtime open to MITM —
an on-path attacker could plant findings on the scanner or read in-flight
request data. Disable per-call by setting `verify_ssl = false`; the CLI
exposes this as `--insecure` and emits a runtime warning when used. Per
HTTP probe, `verify_ssl true|false` in the script overrides the global
setting for that request only.

`max_script_duration` puts a wall-clock cap on a single script run, so a
long-running script (a `for` over a large list of slow probes, long `sleep`s)
cannot pin a tokio worker. The executor checks the budget at the top of
every VM instruction; on exceedance `run()` returns `RuntimeError::Other`
with a message containing `"budget"`.

## SSRF guard on interpolated paths

`HttpRequestSpec.path` is templated and may contain `{{ var }}`
placeholders. When the *literal* `path` is relative, the resolved value is
also required to be relative — an interpolation that expands into a full
URL (`http://169.254.169.254/latest/meta-data`, `http://localhost:6379/…`)
is rejected with `RuntimeError::Other("interpolated path switched to
absolute URL; refusing as SSRF guard: …")`. Scripts that intentionally
probe a separate origin should write the absolute URL into the script
itself; that path is honoured verbatim.

## send_probe flow

1. Resolve probe name in `program.spec.probes`.  
2. `interpolate_socket_spec` — substitute `{{ var }}` in host/payload when payload is valid UTF-8.  
3. Dispatch by `ProbeKind`:

### HTTP

`execute_http` builds a reqwest request from `HttpRequestSpec` + `base_url`, returns `ProbeResponse::Http`. TLS verify follows `HttpRequestSpec.verify_ssl` when set, otherwise `ExecutorConfig.verify_ssl`.

It retries a **transient transport failure** (connection reset, connect/read timeout — never a received response or a TLS-certificate rejection) up to `http_retries` times with a short backoff. A probe re-sent by the script's own `retry` directive passes `0` here, so author-controlled re-sends and the automatic transport retry never multiply.

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

`tokio-rustls` with WebPKI roots when `verify_ssl` is true (the default).
A custom `NoVerifier` is installed only when explicitly requested via
`verify_ssl = false`.

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

`RuntimeError::full_message()` returns the error joined with its full [`source`](https://doc.rust-lang.org/std/error/trait.Error.html#method.source) chain. The wrapped HTTP/I/O variants' `Display` shows only the top layer (`http error: error sending request for url (…)`); `full_message()` appends the real cause (`: client error (Connect): invalid peer certificate: UnknownIssuer`) so callers log it instead of an opaque line. The CLI uses it for every scan/exec failure.

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
2. Compile a `.rsl` script and `Executor::from_bytecode` + manual run.  
3. `format_human` / round-trip `encode` → `decode` for bytecode changes.

Any change to the wire layout bumps `VERSION`, so a mismatched `.rbc` is rejected with a clear `BadVersion` error rather than a cryptic decode failure (see [BYTECODE.md](BYTECODE.md) for the policy). Recompile stored `.rbc` files after a bump.

## IPv6 sockets

Direct socket connect addresses are formatted via
`port_cache::format_socket_addr`, which brackets literal IPv6 addresses so
`::1` becomes `[::1]:443` (the form `TcpStream::connect` requires).
`port_cache` also normalises IPv6 hosts before keying the reachability
cache, so `::1` and `0:0:0:0:0:0:0:1` share one entry. The UDP bind
address tracks the remote family (`[::]:0` for IPv6 targets).

## Header-duplicate handling

reqwest exposes multi-valued response headers (most notably `Set-Cookie`)
as separate entries. The runtime flattens them into one string per header
by joining with `", "` so substring matchers (`header "set-cookie"
contains "HttpOnly"`, etc.) see all values. RFC 7230 §3.2.2 documents this
combining rule; `Set-Cookie` is the standard exception, but substring
matching against the joined string still works for the cookie attributes
scanners typically check.

## Cookie request header

Outbound `cookie name "value"` directives in a single HTTP block are now
emitted as one `Cookie:` request header joined by `"; "` per RFC 6265 §5.4.
The earlier per-call `header("cookie", …)` pattern produced multiple
`Cookie:` headers, which several servers reject outright.

## JSON body encoding

`object_to_json` builds JSON via `serde_json`, so every interpolated value
is escaped as a string literal rather than concatenated. The previous
hand-rolled `escape_json` only handled `\` `"` `\n` `\r` `\t` and left a
JSON-injection vector open against control characters and any value
containing literal `","key":"`. The serde-based path closes that hole.
