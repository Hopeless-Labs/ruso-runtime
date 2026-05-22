# ruso-runtime

> **Development status:** This project is under active development. APIs, bytecode format, and runtime behavior may change without notice. Not recommended for production use yet.

Bytecode VM and network runtime for Ruso vulnerability checks.

## Documentation

Full developer docs are in **[`docs/`](docs/README.md)**:

| Doc | Topic |
|-----|--------|
| [Architecture](docs/ARCHITECTURE.md) | System design, probe table, three repos |
| [Bytecode v1](docs/BYTECODE.md) | Wire format, pools, opcodes |
| [Runtime](docs/RUNTIME.md) | Executor, HTTP/DNS/TCP/UDP, TLS, sessions |
| [Extending](docs/EXTENDING.md) | Adding options, opcodes, matchers |

Related repos: [ruso-script](https://github.com/Hopeless-Labs/ruso-script) (DSL + compiler), [ruso-cli](https://github.com/Hopeless-Labs/ruso-cli) (`ruso` binary).

## Usage

```rust
use ruso_runtime::{Executor, ExecutorConfig, decode_bytecode};

let config = ExecutorConfig {
    base_url: "https://example.com".into(),
    ..Default::default()
};

let program = decode_bytecode(&bytes)?;
let result = Executor::from_bytecode(config, program)?.run().await?;
```

Compile `.ruso` scripts with **[ruso-script](https://github.com/Hopeless-Labs/ruso-script)**; this crate does not parse source files.

## Key types

| Type | Role |
|------|------|
| `BytecodeProgram` | Probes + instructions + pools |
| `Instr` | VM opcodes (`Send`, `Match`, `Repeat`, …) |
| `ProgramSpec` | Probe table + check metadata (cve, cwe, references, cvss, mitigation, …) |
| `Finding` | Single positive result: metadata + evidence |
| `SocketProbeSpec` | Generic dns/tcp/udp options |
| `Executor` | Async execution |

## Bytecode

- Magic: `b"RUSO"`
- Version: **`1`** (`ruso_runtime::VERSION`)

## License

Apache License 2.0. See [LICENSE](LICENSE).
