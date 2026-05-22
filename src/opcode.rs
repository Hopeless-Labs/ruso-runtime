//! Opcode and bytecode wire-format contract (version 2).
//!
//! # File layout (`RUSO` + version byte)
//!
//! 1. Metadata (name, description, impact, severity, author, report title)
//! 2. Probe table (HTTP / DNS / TCP specs)
//! 3. String pool
//! 4. Matcher pool (`QualifiedMatch`)
//! 5. Extract pool (`ExtractSource`)
//! 6. Evidence pool (`EvidenceKind`)
//! 7. Payload pool (raw bytes for `Send` overrides)
//! 8. Instruction stream (`Opcode` discriminants)
//!
//! # Instruction opcodes (wire `u8`)
//!
//! | Byte | Variant     | Payload                          |
//! |------|-------------|----------------------------------|
//! | 1    | Set         | `name_id: u32`, `value_id: u32`  |
//! | 2    | Send        | `probe_id: u32`, optional payload index |
//! | 3    | Match       | `matcher_id: u32`                |
//! | 4    | MatchAll    | `start: u32`, `len: u16`         |
//! | 5    | MatchAny    | `start: u32`, `len: u16`         |
//! | 6    | Assert      | `matcher_id: u32`                |
//! | 7    | Extract     | `name_id: u32`, `source_id: u32` |
//! | 8    | IfMatch     | `matcher_id: u32`, `else_pc: u32`|
//! | 9    | Save        | `from_id: u32`, `to_id: u32`     |
//! | 10   | Evidence    | `kind_id: u32`                   |
//! | 11   | Retry       | `probe_id: u32`, `count: u32`    |
//! | 12   | RetryDelay  | `duration_id: u32`               |
//! | 13   | Sleep       | `duration_id: u32`               |
//! | 14   | Stop        | —                                |
//! | 15   | Fail        | —                                |
//! | 16   | Continue    | —                                |
//! | 17   | Exit        | —                                |
//! | 18   | Repeat      | `count: u32`, `end_pc: u32`      |
//! | 19   | LoopBack    | —                                |
//! | 20   | Break       | —                                |
//!
//! Compilers must emit [`crate::BytecodeProgram`] compatible with [`crate::VERSION`].

pub use crate::runtime::bytecode::{BytecodeProgram, Instr as Opcode, Pc};
pub use crate::runtime::binary::{MAGIC, VERSION};

pub const OP_SET: u8 = 1;
pub const OP_SEND: u8 = 2;
pub const OP_MATCH: u8 = 3;
pub const OP_MATCH_ALL: u8 = 4;
pub const OP_MATCH_ANY: u8 = 5;
pub const OP_ASSERT: u8 = 6;
pub const OP_EXTRACT: u8 = 7;
pub const OP_IF_MATCH: u8 = 8;
pub const OP_SAVE: u8 = 9;
pub const OP_EVIDENCE: u8 = 10;
pub const OP_RETRY: u8 = 11;
pub const OP_RETRY_DELAY: u8 = 12;
pub const OP_SLEEP: u8 = 13;
pub const OP_STOP: u8 = 14;
pub const OP_FAIL: u8 = 15;
pub const OP_CONTINUE: u8 = 16;
pub const OP_EXIT: u8 = 17;
pub const OP_REPEAT: u8 = 18;
pub const OP_LOOP_BACK: u8 = 19;
pub const OP_BREAK: u8 = 20;
