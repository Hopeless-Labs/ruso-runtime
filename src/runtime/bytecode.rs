//! Executable bytecode produced from the script AST.

use crate::contract::{EvidenceKind, ExtractSource, QualifiedMatch};
use crate::runtime::spec::ProgramSpec;

/// Compiled script ready for the executor (probes, metadata, and instruction stream).
#[derive(Debug, Clone)]
pub struct BytecodeProgram {
    pub spec: ProgramSpec,
    pub code: Vec<Instr>,
    pub strings: Vec<String>,
    /// Binary payloads referenced by `Send.payload` (override bytes).
    pub payloads: Vec<Vec<u8>>,
    pub matchers: Vec<QualifiedMatch>,
    pub extracts: Vec<ExtractSource>,
    pub evidence: Vec<EvidenceKind>,
}

/// Instruction pointer index into `BytecodeProgram::code`.
pub type Pc = u32;

#[derive(Debug, Clone, PartialEq)]
pub enum Instr {
    Set {
        name: u32,
        value: u32,
    },
    SetList {
        name: u32,
        start: u32,
        len: u16,
    },
    Send {
        probe: u32,
        payload: Option<u32>,
    },
    Match(u32),
    MatchAll {
        start: u32,
        len: u16,
    },
    MatchAny {
        start: u32,
        len: u16,
    },
    Assert(u32),
    Extract {
        name: u32,
        source: u32,
    },
    IfMatch {
        matcher: u32,
        else_pc: Pc,
    },
    ForList {
        item: u32,
        start: u32,
        len: u16,
        end_pc: Pc,
    },
    ForVar {
        item: u32,
        list: u32,
        end_pc: Pc,
    },
    LoopBack,
    Break,
    Save {
        from: u32,
        to: u32,
    },
    Evidence(u32),
    Retry {
        probe: u32,
        count: u32,
    },
    RetryDelay(u32),
    Sleep(u32),
    Stop,
    Fail,
    Continue,
    Exit,
}

impl BytecodeProgram {
    pub fn instr_count(&self) -> usize {
        self.code.len()
    }
}
