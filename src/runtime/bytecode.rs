//! Executable bytecode produced from the script AST.

use crate::contract::{EvidenceKind, ExtractSource, QualifiedMatch};
use crate::runtime::spec::ProgramSpec;

/// Compiled script ready for the executor (probes, metadata, and instruction stream).
#[derive(Debug, Clone)]
pub struct BytecodeProgram {
    /// Probe table and finding metadata (the non-executable part).
    pub spec: ProgramSpec,
    /// The instruction stream the executor walks.
    pub code: Vec<Instr>,
    /// String pool. Instruction operands index into this.
    pub strings: Vec<String>,
    /// Binary payloads referenced by `Send.payload` (override bytes).
    pub payloads: Vec<Vec<u8>>,
    /// Matcher pool, indexed by `Match`/`Assert`/`IfMatch` operands.
    pub matchers: Vec<QualifiedMatch>,
    /// Extract-rule pool, indexed by `Extract` operands.
    pub extracts: Vec<ExtractSource>,
    /// Evidence-rule pool, indexed by `Evidence` operands.
    pub evidence: Vec<EvidenceKind>,
}

/// Instruction pointer index into `BytecodeProgram::code`.
pub type Pc = u32;

/// A single VM instruction. Operands are `u32`/`u16` indices into the
/// program's pools (`strings`, `matchers`, `extracts`, `evidence`) or program
/// counters ([`Pc`]) into `code` — never inline data.
#[derive(Debug, Clone, PartialEq)]
pub enum Instr {
    /// Set a string variable: `name` and `value` index the string pool.
    Set {
        /// String-pool index of the variable name.
        name: u32,
        /// String-pool index of the value.
        value: u32,
    },
    /// Set a list variable from `len` consecutive strings starting at `start`.
    SetList {
        /// String-pool index of the variable name.
        name: u32,
        /// String-pool index of the first element.
        start: u32,
        /// Number of elements.
        len: u16,
    },
    /// Perform a probe's request. `payload`, if set, overrides the probe's
    /// payload (string-pool or payload-pool index, per probe kind).
    Send {
        /// String-pool index of the probe name.
        probe: u32,
        /// Optional payload-override index.
        payload: Option<u32>,
    },
    /// Evaluate one matcher (matcher-pool index); on failure, latch the match
    /// chain false.
    Match(u32),
    /// Evaluate `len` matchers starting at `start`; all must pass.
    MatchAll {
        /// Matcher-pool index of the first matcher.
        start: u32,
        /// Number of matchers.
        len: u16,
    },
    /// Evaluate `len` matchers starting at `start`; any one passing succeeds.
    MatchAny {
        /// Matcher-pool index of the first matcher.
        start: u32,
        /// Number of matchers.
        len: u16,
    },
    /// Like `Match`, but a failure aborts the run with an error.
    Assert(u32),
    /// Extract a value into a variable. `name` is a string-pool index; `source`
    /// indexes the extract pool.
    Extract {
        /// String-pool index of the destination variable name.
        name: u32,
        /// Extract-pool index of the source rule.
        source: u32,
    },
    /// If the matcher holds, fall through; otherwise jump to `else_pc`.
    IfMatch {
        /// Matcher-pool index of the condition.
        matcher: u32,
        /// Program counter to jump to when the condition is false.
        else_pc: Pc,
    },
    /// Begin a `for` over a literal list (`len` strings from `start`), binding
    /// each to `item`. `end_pc` is the instruction after the loop.
    ForList {
        /// String-pool index of the loop variable name.
        item: u32,
        /// String-pool index of the first value.
        start: u32,
        /// Number of values.
        len: u16,
        /// Program counter just past the loop.
        end_pc: Pc,
    },
    /// Begin a `for` over a list variable (`list`), binding each to `item`.
    ForVar {
        /// String-pool index of the loop variable name.
        item: u32,
        /// String-pool index of the list variable name.
        list: u32,
        /// Program counter just past the loop.
        end_pc: Pc,
    },
    /// End-of-loop-body marker: advance the loop or exit it.
    LoopBack,
    /// Exit the innermost loop.
    Break,
    /// Snapshot a probe's response under another name (`from`/`to` index the
    /// string pool).
    Save {
        /// String-pool index of the source probe name.
        from: u32,
        /// String-pool index of the destination name.
        to: u32,
    },
    /// Attach evidence (evidence-pool index) when the match chain is true.
    Evidence(u32),
    /// Re-send a probe up to `count` times, stopping on first success.
    Retry {
        /// String-pool index of the probe name.
        probe: u32,
        /// Maximum attempts.
        count: u32,
    },
    /// Set the delay between `Retry` attempts (string-pool index of a duration).
    RetryDelay(u32),
    /// Sleep for a duration (string-pool index of a duration literal).
    Sleep(u32),
    /// Stop the run, emitting no finding.
    Stop,
    /// Abort the run with an error.
    Fail,
    /// Skip to the next iteration of the innermost loop.
    Continue,
    /// Stop the run, emitting the finding if the match chain held.
    Exit,
}

impl BytecodeProgram {
    /// Number of instructions in the program's `code` stream.
    pub fn instr_count(&self) -> usize {
        self.code.len()
    }
}
