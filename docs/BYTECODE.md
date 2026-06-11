# Bytecode and opcodes (v1)

Compiled output is a `BytecodeProgram` defined in `ruso-runtime/src/runtime/bytecode.rs`. The on-disk / on-wire format is implemented in `runtime/binary.rs`.

Constants:

```rust
pub const MAGIC: &[u8; 4] = b"RUSO";
pub const VERSION: u8 = 1;
```

## Versioning policy

The header carries a one-byte `VERSION` (currently **1**). The decoder accepts
**only** that exact version; anything else is rejected up front with
`BytecodeError::BadVersion { found, supported }` ("unsupported bytecode version
N (this build reads version M)") — never a cryptic mid-decode `Corrupt` error.

**Any change to the wire format must bump `VERSION`.** Early-development
revisions evolved the v1 layout *in place* without bumping (folding changes back
into v1), which is why a stale `.rbc` could fail to decode with an opaque "string
length exceeds buffer" instead of a clean version error. That era is over: now
that bytecode is cached locally and distributed via the registry, a format
change is a version bump.

> A `VERSION` bump is a **coordinated** change: the registry must deploy the new
> runtime and serve (re-compile) `VERSION`-N bytecode, otherwise clients on the
> new version reject everything the registry still serves as old. The local
> install cache self-heals (an undecodable entry is re-fetched), so once the
> registry serves the new version, clients converge automatically.

Removing an opcode is *not* a format change as long as the remaining opcode
numbers are stable and no valid program used the removed one — those byte
streams are identical. (That is why dropping `repeat`/`OP_REPEAT` left `VERSION`
at 1; opcode 18 is reserved.)

The current v1 layout:

- Encodes `CmpValue::Number` as `u64` (earlier development revisions
  truncated to `u32`).
- Assigns HTTP method tags 5 and 6 to `Head` and `Options`.
- Bounds every untrusted list/count against the remaining buffer in the
  decoder, so a malicious or corrupt `.rbc` file cannot trigger OOM
  allocations from a `u32::MAX` count.
- Bounds-checks every instruction operand index against its pool after
  decoding (see [Operand validation](#operand-validation-decoder-hardening)),
  so an out-of-range index surfaces as a `Corrupt` error instead of
  panicking the executor.

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

CLI `compile` emits hex; `exec` accepts hex files. The runtime
`load_bytecode_input` helper used to accept an `@path` prefix to read a file
directly; that overload has been removed to keep file IO inside the CLI and
prevent any caller from passing less-trusted hex text through a
path-traversal sink.

## Bounded counts (decoder hardening)

Every `u32` count field that drives a `Vec::with_capacity(count)` is now
validated against the remaining buffer in the same step:

```rust
let raw = r.u32()?;
let count = r.bounded_count(raw)?; // errors if count > remaining bytes
let mut out = Vec::with_capacity(count);
```

Without this guard a corrupt or hostile bytecode could set
`count = u32::MAX`, triggering a multi-GB allocation and killing the
scanner before the rest of the buffer was inspected.

The bound also applies to the length-prefixed `str` and `opt_bytes` readers,
so an inner `len` field that overruns the buffer is rejected before the
allocation, not after.

## Operand validation (decoder hardening)

Bounded counts stop OOM allocations, but they do not check that an
instruction's operand indices land inside the decoded pools — those
indices are plain `u32`s in the code stream, and the executor indexes
`strings`, `payloads`, `matchers`, `extracts`, and `evidence` directly.
An unchecked out-of-range index (e.g. `Set { name: u32::MAX }`) would
panic the worker thread.

After the whole program is decoded, `validate_program` walks the code
once and rejects any operand index `>= pool.len()` (and any
`start + len` slice that overruns, computed in `usize` so it can't wrap)
with a `Corrupt` error. Jump targets (`else_pc`, `end_pc`) are exempt:
the executor's main loop halts once `pc >= code.len()`, so an
out-of-range jump simply ends execution without reading out of bounds.

## HTTP methods (wire tag)

| Tag | Method |
|-----|--------|
| 0 | `GET` |
| 1 | `POST` |
| 2 | `PUT` |
| 3 | `PATCH` |
| 4 | `DELETE` |
| 5 | `HEAD` |
| 6 | `OPTIONS` |

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
| 18 | *(reserved)* | was `Repeat`, removed |
| 19 | `LoopBack` | — |
| 20 | `Break` | — |
| 21 | `SetList` | `name_id: u32`, `start: u32`, `len: u16` |
| 22 | `ForList` | `item_id: u32`, `start: u32`, `len: u16`, `end_pc: u32` |
| 23 | `ForVar` | `item_id: u32`, `list_id: u32`, `end_pc: u32` |

Public constants: `ruso_runtime::opcode::{OP_*}`.

## CmpValue encoding

| Tag | Variant | Wire |
|-----|---------|------|
| 0 | `Number(u64)` | `u64` little-endian |
| 1 | `String(String)` | length-prefixed UTF-8 |
| 2 | `Duration(String)` | length-prefixed UTF-8 |

The `Number` payload is encoded as `u64`. Earlier in-development revisions
truncated to `u32`; scripts that compare against values above ~4.3 billion
(e.g. `response_size > 5_000_000_000`) now round-trip without silent loss.

## Control-flow patching

The compiler emits placeholders and patches PCs:

- **`IfMatch`** — `else_pc` set after body is emitted.
- **`ForList`** — `end_pc` set after `LoopBack` is emitted.

Executor semantics:

- **`ForList`** — pushes a `LoopFrame` over the literal list, binding the item variable each iteration.
- **`LoopBack`** — advances the `for` iterator; if more items remain, jump to `head_pc`, else pop frame and continue after loop.
- **`Break`** — pop innermost frame, jump to `end_pc`.

The executor also enforces a **wall-clock budget**
(`ExecutorConfig::max_script_duration`, default 5 minutes), checked at
instruction boundaries, so a long-running script (e.g. a `for` over a large
list of slow probes) cannot keep a tokio worker busy beyond that budget.

## Metadata section

Written in order after the header (`MAGIC` + `VERSION`):

| Field | Encoding |
|-------|----------|
| `name` | optional UTF-8 string |
| `description` | optional string |
| `impact` | optional string |
| `severity` | `u8` tag (0=absent, else 1–5 for low…critical) |
| `author` | optional string |
| `report_title` | optional string (`report` in RSL) |
| `cve` | `u32` count + strings |
| `cwe` | `u32` count + strings |
| `references` | `u32` count + strings |
| `cvss` | `u32` count + strings (vector) |
| `cvss_score` | `u32` count + strings (numeric score) |
| `mitigation` | `u32` count + strings |
| `tags` | `u32` count + strings (discovery labels) |
| `version` | optional UTF-8 string (SemVer, required at publish) |
| `family` | optional UTF-8 string (single curated category) |

Each string list uses the same `write_strings` / `read_strings` helper as the string pool (count, then length-prefixed UTF-8 per entry). Repeatable metadata lines in `.rsl` append to these lists at compile time.

`version` and `family` are written at the tail of the metadata block via `opt_str` (a `0`/`1` presence byte then the string). They were appended in place during `0.1.0-dev` without bumping the version byte — older `.rbc` that predate them simply won't have the trailing bytes, so always recompile after pulling.

## Pools and IDs

All `u32` IDs index into compile-time pools in `BytecodeProgram`:

- Strings — probe names, variable names, duration text for sleep/retry
- Payloads — binary overrides for `Send`
- Matchers — full `QualifiedMatch` structs
- Extracts / Evidence — parallel structures

Evidence pool entries (`EvidenceKind`):

| Tag | Form | Wire |
|-----|------|------|
| 0 | `body <probe>` | probe name string |
| 1 | `regex <probe> <pattern>` | probe name + pattern string |
| 2 | `response <probe>` | probe name string |

The executor resolves IDs at runtime via `program.strings[id]`, etc.

## Disassembly

```rust
use ruso_runtime::format_human;

let text = format_human(&bytecode);
```

Human listing is in `runtime/disasm.rs` (metadata, probes, pools, annotated instructions). String spans referenced by `ForList`/`SetList` are looked up via `.get()` rather than indexed, so corrupt-but-decodable bytecode that points past the string pool no longer panics the disassembler.

## Embedding bytecode

```rust
use ruso_runtime::{Executor, ExecutorConfig, decode_bytecode};

let program = decode_bytecode(&bytes)?;
let executor = Executor::from_bytecode(config, program)?;
let result = executor.run().await?;
```

Compilers **must** target `VERSION` 1. While `0.1.0-dev` the v1 wire format
may change between commits without a version bump — recompile stored `.rbc`
files after pulling.

## Design note: why not more opcodes?

Protocol-specific opcodes (`OP_SMTP`, `OP_REDIS`, …) would couple the VM to services. Ruso keeps:

- **Data** in the probe table (payload bytes, ports, TLS flag).
- **Control** in a small ISA (`Send`, `Match`, `ForList`, …).

New network behavior should prefer new **socket options** or **send overrides** before new opcodes.
