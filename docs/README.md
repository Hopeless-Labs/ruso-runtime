# Ruso runtime documentation

Documentation for the **ruso-runtime** crate: bytecode VM, wire format, and network execution.

## Reading order

1. **[Architecture](ARCHITECTURE.md)** — three crates, probe table vs opcodes, socket model, execution state.
2. **[Bytecode v1](BYTECODE.md)** — `RUSO` header, pools, instruction encoding.
3. **[Runtime](RUNTIME.md)** — `Executor`, HTTP/DNS/TCP/UDP, TLS, sessions, multi-read.
4. **[Extending](EXTENDING.md)** — new socket options, opcodes, matchers, transports.

## Glossary

| Term | Meaning |
|------|---------|
| **Probe** | Named request in the probe table (`http home`, `tcp redis`, …) |
| **Send** | Opcode that runs a probe and stores `ProbeResponse` |
| **Bytecode** | `BytecodeProgram`: probes + `Vec<Instr>` + pools |
| **Socket probe** | Generic `host` / `port` / `payload` (+ `tls`, `session`, `read_*`) |

## Versioning

| Constant | Value | Location |
|----------|-------|----------|
| Magic | `b"RUSO"` | `ruso_runtime::MAGIC` |
| Wire format | **1** | `ruso_runtime::VERSION` |

## Other repositories

| Topic | Repository |
|-------|------------|
| `.ruso` DSL syntax | [ruso-script](https://github.com/Hopeless-Labs/ruso-script) — `docs/DSL_REFERENCE.md` |
| Compiler pipeline | [ruso-script](https://github.com/Hopeless-Labs/ruso-script) — `docs/COMPILER.md` |
| Example checks | [ruso-script](https://github.com/Hopeless-Labs/ruso-script) — `examples/`, `docs/EXAMPLES.md` |
| `ruso` CLI | [ruso-cli](https://github.com/Hopeless-Labs/ruso-cli) — `docs/CLI.md` |

## Source map

| Path | Purpose |
|------|---------|
| `src/opcode.rs` | Opcode IDs and module-level ISA docs |
| `src/contract.rs` | Matchers, severity, evidence |
| `src/runtime/executor.rs` | VM main loop |
| `src/runtime/binary.rs` | Encode/decode v1 |
| `src/runtime/session.rs` | TCP/TLS sessions, UDP |
| `src/runtime/socket.rs` | One-shot and session I/O |
| `src/runtime/http.rs` | HTTP client |
| `src/runtime/dns.rs` | Resolver vs wire UDP |
