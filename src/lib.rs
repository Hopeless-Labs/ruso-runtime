//! Ruso VM: execute compiled bytecode against HTTP, DNS, TCP, and UDP targets.
//!
//! Compilers (e.g. `ruso-script`) must target [`opcode::VERSION`] and the
//! instruction set documented in [`opcode`].
//!
//! # Developer documentation
//!
//! - [Architecture](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/ARCHITECTURE.md)
//! - [Bytecode v1](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/BYTECODE.md)
//! - [Runtime](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/RUNTIME.md)
//! - [Extending](https://github.com/Hopeless-Labs/ruso-runtime/blob/main/docs/EXTENDING.md)

// `ProbeKind::Http` is the dominant variant by a wide margin (HTTP spec carries
// headers, cookies, queries, bodies). Boxing it would force an indirection on
// every probe access; the size asymmetry is intentional.
#![allow(clippy::large_enum_variant)]

pub mod contract;
pub mod opcode;
mod runtime;
pub mod util;

pub use contract::{
    BodyValue, CmpOp, CmpValue, EvidenceKind, ExtractSource, FieldKind, HttpMethod, InlinePart,
    InlinePartBody, MatchPredicate, ObjectBody, QualifiedField, QualifiedMatch, Severity,
};
pub use opcode::{BytecodeProgram, MAGIC, Opcode, Pc, VERSION};
pub use runtime::duration::parse_duration;
pub use runtime::http::build_client;
pub use runtime::{
    BytecodeError, CheckMetadata, ExecutionResult, Executor, ExecutorConfig, Finding,
    HttpRequestSpec, PortCache, PortCheck, ProbeKind, ProgramSpec, Report, RuntimeError,
    SocketProbeSpec, VariableValue, bytes_to_hex, bytes_to_hex_dump, decode_bytecode, disasm,
    encode_bytecode, format_human, hex_to_bytes, load_bytecode_input,
};
pub use util::truncate_str;
