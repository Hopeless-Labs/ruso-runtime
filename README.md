# ruso-runtime

Bytecode VM and network runtime for Ruso vulnerability checks.

## Documentation

- [Architecture](../docs/ARCHITECTURE.md)
- [Bytecode v2](../docs/BYTECODE.md)
- [Runtime guide](../docs/RUNTIME.md)
- [Extending](../docs/EXTENDING.md)

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

Compile scripts with the **`ruso-script`** crate; this crate does not parse `.ruso` files.

## Key types

| Type | Role |
|------|------|
| `BytecodeProgram` | Probes + instructions + pools |
| `Instr` | VM opcodes (`Send`, `Match`, `Repeat`, …) |
| `ProgramSpec` | Probe table + check metadata |
| `SocketProbeSpec` | Generic dns/tcp/udp options |
| `Executor` | Async execution |

## Bytecode

- Magic: `b"RUSO"`
- Version: **`2`** (`ruso_runtime::VERSION`)

## License

Apache License 2.0. See [LICENSE](LICENSE).
