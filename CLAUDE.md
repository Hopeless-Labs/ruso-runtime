# ruso-runtime — guidance for Claude

The bytecode VM and network runtime: executes compiled `.rbc` programs against
HTTP, DNS, TCP, and UDP targets and emits findings.

Documentation lives in **The Ruso Book** (<https://docs.ruso.hopeless-labs.com>),
not in this repo — the local `docs/` was removed; the book is the single source.

## Quality gate (keep green before any commit)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test
```

## Conventions

- **Bytecode binary format: MAGIC `b"RUSO"`, `VERSION = 1`.** Do **not** bump
  `VERSION` unless the wire format actually changes — it's a coordinated step
  (the registry must redeploy and re-serve recompiled bytecode).
- Prefer small, **network-free regression tests**: build a `BytecodeProgram`,
  run the `Executor`, and assert on the result (see the loop-opcode tests).
- VM loop borrow pattern: decide an action *while* borrowing the loop frame,
  then mutate `context` *after* the borrow ends (the two can't overlap).
- Keep `///` docs accurate — the book's `/api` rustdoc is generated from them.
- **Don't bump the version on every change** — accumulate notes under the
  current `0.1.0-beta.x` heading in `CHANGELOG.md`.
- Match the surrounding code's style and comment density.
