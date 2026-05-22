# Bytecode and opcodes (v1)

Compiled output is a `BytecodeProgram` defined in `ruso-runtime/src/runtime/bytecode.rs`. The on-disk / on-wire format is implemented in `runtime/binary.rs`.

Constants:

```rust
pub const MAGIC: &[u8; 4] = b"RUSO";
pub const VERSION: u8 = 1;
```

## File layout

Sections are written in order:

| # | Section | Content |
|---|---------|---------|
| 1 | Header | `MAGIC` + `VERSION` |
| 2 | Metadata | See [Metadata section](#metadata-section) |
| 3 | Probe table | count + `(name, ProbeKind)*` |
| 4 | String pool | UTF-8 strings (identifiers, durations as text, …) |
| 5 | Payload pool | raw byte blobs for `Send` overrides |
| 6 | Matcher pool | `QualifiedMatch` entries |
| 7 | Extract pool | `ExtractSource` entries |
| 8 | Evidence pool | `EvidenceKind` entries |
| 9 | Code | instruction stream |

CLI `compile` emits hex; `exec` accepts hex or `@file.bc`.

## Probe kinds (wire tag)

| Tag | Variant | Body |
|-----|---------|------|
| `0` | `Http` | `HttpRequestSpec` (method, path, options, bodies, …) |
| `1` | `Dns` | `SocketProbeSpec` |
| `2` | `Tcp` | `SocketProbeSpec` |
| `3` | `Udp` | `SocketProbeSpec` |

### SocketProbeSpec

Binary order:

1. `host` — length-prefixed UTF-8 string  
2. `port` — optional `u16` (`u8` flag + value)  
3. `payload` — optional byte blob (`u8` flag + `u32` len + bytes)  
4. `tls` — `u8` (0/1)  
5. `session` — `u8` (0/1)  
6. `read_max` — `u32`  
7. `read_idle_ms` — `u32`  

## Instruction set

Wire opcode byte → `Instr` variant:

| Op | Name | Operands |
|----|------|----------|
| 1 | `Set` | `name_id: u32`, `value_id: u32` |
| 2 | `Send` | `probe_id: u32`, `has_payload: u8`, optional `payload_id: u32` |
| 3 | `Match` | `matcher_id: u32` |
| 4 | `MatchAll` | `start: u32`, `len: u16` |
| 5 | `MatchAny` | `start: u32`, `len: u16` |
| 6 | `Assert` | `matcher_id: u32` |
| 7 | `Extract` | `name_id: u32`, `source_id: u32` |
| 8 | `IfMatch` | `matcher_id: u32`, `else_pc: u32` |
| 9 | `Save` | `from_id: u32`, `to_id: u32` |
| 10 | `Evidence` | `kind_id: u32` |
| 11 | `Retry` | `probe_id: u32`, `count: u32` |
| 12 | `RetryDelay` | `duration_id: u32` (string pool) |
| 13 | `Sleep` | `duration_id: u32` |
| 14 | `Stop` | — |
| 15 | `Fail` | — |
| 16 | `Continue` | — |
| 17 | `Exit` | — |
| 18 | `Repeat` | `count: u32`, `end_pc: u32` |
| 19 | `LoopBack` | — |
| 20 | `Break` | — |

Public constants: `ruso_runtime::opcode::{OP_*}`.

## Control-flow patching

The compiler emits placeholders and patches PCs:

- **`IfMatch`** — `else_pc` set after body is emitted.  
- **`Repeat`** — `end_pc` set after `LoopBack` is emitted.

Executor semantics:

- **`Repeat`** — pushes `LoopFrame { remaining: count, head_pc: pc+1, end_pc }`, enters body.  
- **`LoopBack`** — decrements `remaining`; if `> 0`, jump to `head_pc`, else pop frame and continue after loop.  
- **`Break`** — pop innermost frame, jump to `end_pc`.

## Metadata section

Written in order after the header (`MAGIC` + `VERSION`):

| Field | Encoding |
|-------|----------|
| `name` | optional UTF-8 string |
| `description` | optional string |
| `impact` | optional string |
| `severity` | `u8` tag (0=absent, else 1–5 for low…critical) |
| `author` | optional string |
| `report_title` | optional string (`report` in DSL) |
| `cve` | `u32` count + strings |
| `cwe` | `u32` count + strings |
| `references` | `u32` count + strings |

Each string list uses the same `write_strings` / `read_strings` helper as the string pool (count, then length-prefixed UTF-8 per entry). Repeatable `cve` / `cwe` / `references` lines in `.ruso` append to these lists at compile time.

## Pools and IDs

All `u32` IDs index into compile-time pools in `BytecodeProgram`:

- Strings — probe names, variable names, duration text for sleep/retry  
- Payloads — binary overrides for `Send`  
- Matchers — full `QualifiedMatch` structs  
- Extracts / Evidence — parallel structures  

The executor resolves IDs at runtime via `program.strings[id]`, etc.

## Disassembly

```rust
use ruso_runtime::format_human;

let text = format_human(&bytecode);
```

Human listing is in `runtime/disasm.rs` (metadata, probes, pools, annotated instructions).

## Embedding bytecode

```rust
use ruso_runtime::{Executor, ExecutorConfig, decode_bytecode};

let program = decode_bytecode(&bytes)?;
let executor = Executor::from_bytecode(config, program)?;
let result = executor.run().await?;
```

Compilers **must** target `VERSION` 1. Recompile stored `.bc` files after metadata layout changes. Bump `VERSION` when changing probe or `Send` encoding.

## Design note: why not more opcodes?

Protocol-specific opcodes (`OP_SMTP`, `OP_REDIS`, …) would couple the VM to services. Ruso keeps:

- **Data** in the probe table (payload bytes, ports, TLS flag).  
- **Control** in a small ISA (`Send`, `Match`, `Repeat`, …).

New network behavior should prefer new **socket options** or **send overrides** before new opcodes.
