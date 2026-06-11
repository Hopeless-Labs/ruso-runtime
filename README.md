# ruso-runtime

> [!NOTE]
> **Development status:** under active development. APIs, bytecode format, and
> runtime behavior may change without notice. Not recommended for production use yet.

Bytecode VM and network runtime for Ruso vulnerability checks — executes compiled
`.rbc` programs against HTTP, DNS, TCP, and UDP targets. Part of the
[Ruso](https://github.com/Hopeless-Labs) vulnerability-scanning ecosystem.

📖 **Full documentation:** <https://docs.ruso.hopeless-labs.com>
(architecture, bytecode format, runtime internals, extending).

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

This crate executes bytecode; it does not parse source. Compile `.rsl` with
**[ruso-script](https://github.com/Hopeless-Labs/ruso-script)**.

Dependency:

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
```

## Bytecode

- Magic: `b"RUSO"`
- Version: **`1`** (`ruso_runtime::VERSION`)

The wire format, opcodes, and execution model are documented in
**[The Ruso Book](https://docs.ruso.hopeless-labs.com)**.

## License

Apache License 2.0. See [LICENSE](LICENSE).
