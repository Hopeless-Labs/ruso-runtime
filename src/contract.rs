//! Shared types embedded in Ruso bytecode (constant pools and probe specs).
//!
//! `ruso-script` parses source into an AST that uses these types for matchers,
//! bodies, and metadata so compiled output matches what `ruso-runtime` executes.

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObjectBody {
    pub pairs: Vec<(String, BodyValue)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BodyValue {
    String(String),
    Interpolation(String),
    Object(ObjectBody),
    Bytes(String),
    Part(InlinePart),
}

#[derive(Debug, Clone, PartialEq)]
pub struct InlinePart {
    pub filename: Option<String>,
    pub body: InlinePartBody,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InlinePartBody {
    Text(String),
    Bytes(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct QualifiedField {
    pub target: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    Status,
    Body,
    Header(String),
    ResponseTime,
    ResponseSize,
    /// Resolver answers (`dns` without `port` / `payload`).
    Answer,
    /// Raw probe bytes (tcp / udp / wire dns). Alias: `banner` in scripts.
    Response,
    Banner,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QualifiedMatch {
    pub field: QualifiedField,
    pub predicate: MatchPredicate,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MatchPredicate {
    Compare {
        op: CmpOp,
        value: CmpValue,
    },
    Contains(String),
    NotContains(String),
    Regex(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtractSource {
    Body {
        target: String,
        regex: Option<String>,
    },
    Header {
        target: String,
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceKind {
    BodyRef(String),
    Regex(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CmpValue {
    Number(u64),
    String(String),
    Duration(String),
}
