# Extending Ruso

Guide for maintainers adding features without breaking the generic probe model.

## Decision tree

```
New vulnerability check for existing transport?
  └─ Yes → add .rsl under examples/ or your checks repo (no Rust)

New socket behavior (TLS client cert, SCTP, …)?
  └─ Extend SocketProbeSpec + session layer + grammar

New control flow (while, goto)?
  └─ New Instr + compiler + executor + opcode doc + VERSION bump if needed

New protocol family unrelated to HTTP/socket bytes?
  └─ New ProbeKind variant + executor arm (rare; prefer socket first)
```

## Adding a check (script only)

1. Create `my_check.rsl` with metadata + probe + `send` + `match`.  
2. `ruso validate --script my_check.rsl`  
3. Test with `ruso scan` against a lab target.  
4. Ship the `.rsl` file; no runtime release required.

Use hex payload for binary protocols; `session` (and multiple `send`s) for multi-step dialogs.

Optional `cve`, `cwe`, `references`, `cvss`, and `cvss_score` lines (repeatable) plus a single `mitigation` line (free text; declaring it more than once is a compile error) attach advisory IDs, CVSS vectors/scores, remediation text, and URLs to findings and CLI/JSON reports.

## Adding a metadata field

Example: a new `tags` list on checks.

| Step | File |
|------|------|
| 1 | `grammar.pest` — keyword + `metadata_stmt` arm |
| 2 | `ast.rs` — `Stmt` variant |
| 3 | `parser/metadata.rs` + `spec_build.rs` |
| 4 | `spec.rs` — `CheckMetadata` field |
| 5 | `binary.rs` — `write_metadata` / `read_metadata` (append at end of metadata block) |
| 6 | `report.rs` / `disasm.rs` — `Finding` + listing |
| 7 | `docs/RSL_REFERENCE.md`, `BYTECODE.md`, `RUNTIME.md` |
| 8 | `ruso-cli` `report.rs` if exposed in scan output |
| 9 | Recompile all `.rbc` files; bump `VERSION` only if probe or instruction layout changes |

## Adding a socket probe option

Example: `connect_timeout 5s`.

| Step | File |
|------|------|
| 1 | `grammar.pest` — `kw_connect_timeout ~ duration` in `socket_item` |
| 2 | `ast.rs` — field on `SocketProbe` |
| 3 | `parser/socket.rs` — parse duration → ms or store string |
| 4 | `spec.rs` — `SocketProbeSpec` field + `Default` |
| 5 | `spec_build.rs` — copy field |
| 6 | `binary.rs` — encode/decode after existing fields |
| 7 | `session.rs` / `executor.rs` — use value on connect |
| 8 | `disasm.rs` — show in probe dump |
| 9 | `docs/RSL_REFERENCE.md` — document |
| 10 | Bump `VERSION` if layout changes |

Backward compatibility: old bytecode cannot read new fields—bump version and recompile all stored `.rbc` files.

## Adding an instruction

Example: `close <probe>` to drop session.

| Step | File |
|------|------|
| 1 | `grammar.pest` + `ast::Stmt` |
| 2 | `compile.rs` — emit `Instr::Close(probe_id)` |
| 3 | `bytecode.rs` — enum variant |
| 4 | `binary.rs` — `OP_CLOSE`, write/read |
| 5 | `opcode.rs` — constant + table row |
| 6 | `executor.rs` — remove from `context.sessions` |
| 7 | `disasm.rs` — format line |
| 8 | Syntax test in `syntax_tests.rs` |

Prefer reusing `Send` + `session false` + new probe if semantics allow—fewer opcodes stay easier to reason about.

## Adding a matcher field

Example: `cert_cn` on TLS socket responses (hypothetical).

1. `contract::FieldKind` variant.  
2. `matcher.rs` — read from response (may need to store TLS info on `SocketResponse`).  
3. `grammar.pest` — `kw_cert_cn` in `qualified_field`.  
4. `match_expr.rs` — map to `FieldKind`.  
5. Binary matcher encode in `binary.rs` if already generic—field kinds are tagged on wire.

## HTTP extensions

Extend `HttpItem` in AST, `http_item` in grammar, `probes.rs`, `write_http_spec` / `read_http_spec`, and `execute_http`.

HTTP stays separate from `SocketProbeSpec` intentionally.

## Contract sharing

Types in `ruso-runtime/src/contract.rs` are shared with the compiler via `ruso_script::ast` re-exports. Changing matchers affects **both** crates—publish runtime first, then bump script dependency.

## Testing checklist

- [ ] `cargo build` all three crates  
- [ ] `cargo test -p ruso-script` (parser)  
- [ ] `cargo test -p ruso-runtime` (unit tests)  
- [ ] `ruso validate` on affected examples  
- [ ] Round-trip `compile` → `decode` → `encode` for bytecode changes  
- [ ] One live `scan` against lab service  

## Anti-patterns

| Avoid | Prefer |
|-------|--------|
| `OP_REDIS`, `OP_SMTP` | `tcp` + payload |
| Forking executor per CVE | Parameterized `.rsl` |
| Raw SQL in scripts | Not applicable—keep I/O in runtime |
| Breaking `VERSION` without bump | Explicit migration notes |

## Multi-repo dependency graph

```text
ruso-cli → ruso-script → ruso-runtime
```

Each crate is its own Git repository. Published `Cargo.toml` files use **git dependencies** on `main`:

```toml
ruso-runtime = { git = "https://github.com/Hopeless-Labs/ruso-runtime.git", branch = "main" }
ruso-script = { git = "https://github.com/Hopeless-Labs/ruso-script.git", branch = "main" }
```

For local work on all three at once, clone them as siblings and temporarily use `path = "../ruso-*"` in `Cargo.toml`, or add a `[patch]` table in the crate you are building.

When publishing to crates.io later, semver the runtime contract (`VERSION`, public types) independently from RSL.

## Future directions (not implemented)

Documented for planning only:

- `--target` overrides socket `host` / `port`  
- `while` / `for` with variables  
- Byte-level matchers (`match hex`)  
- ICMP probe kind  
- Check signing / attestation of bytecode  

These should follow the same probe-table + small-ISA pattern.
