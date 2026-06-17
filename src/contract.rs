//! Shared types embedded in Ruso bytecode (constant pools and probe specs).
//!
//! `ruso-script` parses source into an AST that uses these types for matchers,
//! bodies, and metadata so compiled output matches what `ruso-runtime` executes.

/// Finding severity, in ascending order of urgency (`Info` is the catch-all
/// used when a check declares no `severity`).
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    /// Low impact.
    Low,
    /// Moderate impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact — typically remote code execution or full compromise.
    Critical,
    /// Informational; no direct security impact. The default when unset.
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

/// HTTP request method for an `http` probe.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpMethod {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `HEAD`
    Head,
    /// `OPTIONS`
    Options,
}

/// A structured request body (`data { … }` / `json { … }`): ordered key/value
/// pairs. Order is preserved so serialization is deterministic.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectBody {
    /// Key/value pairs in source order.
    pub pairs: Vec<(String, BodyValue)>,
}

/// A value inside an [`ObjectBody`] or multipart body.
#[derive(Debug, Clone, PartialEq)]
pub enum BodyValue {
    /// A literal string.
    String(String),
    /// A string containing `{{ var }}` placeholders to interpolate at runtime.
    Interpolation(String),
    /// A nested object.
    Object(ObjectBody),
    /// Hex-encoded raw bytes.
    Bytes(String),
    /// A multipart part.
    Part(InlinePart),
}

/// One part of a multipart request body.
#[derive(Debug, Clone, PartialEq)]
pub struct InlinePart {
    /// Optional `filename` for a file part.
    pub filename: Option<String>,
    /// The part's content.
    pub body: InlinePartBody,
}

/// The content of an [`InlinePart`].
#[derive(Debug, Clone, PartialEq)]
pub enum InlinePartBody {
    /// UTF-8 text.
    Text(String),
    /// Hex-encoded raw bytes.
    Bytes(String),
}

/// A response field selector: which probe (`target`) and which part of its
/// response (`kind`) a matcher or evidence rule reads.
#[derive(Debug, Clone, PartialEq)]
pub struct QualifiedField {
    /// The probe name the field belongs to (e.g. `home`).
    pub target: String,
    /// Which part of the response to read.
    pub kind: FieldKind,
}

/// Which part of a probe response a matcher reads.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    /// HTTP status code.
    Status,
    /// HTTP response body.
    Body,
    /// A named HTTP response header.
    Header(String),
    /// HTTP round-trip time.
    ResponseTime,
    /// HTTP response body size in bytes.
    ResponseSize,
    /// Resolver answers (`dns` without `port` / `payload`).
    Answer,
    /// Raw probe bytes (tcp / udp / wire dns). Alias: `banner` in scripts.
    Response,
    Banner,
}

/// A single matcher: a response [field](QualifiedField) tested against a
/// [predicate](MatchPredicate).
#[derive(Debug, Clone, PartialEq)]
pub struct QualifiedMatch {
    /// The response field to read.
    pub field: QualifiedField,
    /// The condition the field must satisfy.
    pub predicate: MatchPredicate,
}

/// The condition a [`QualifiedField`] is tested against.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchPredicate {
    /// Numeric/string/duration comparison (`==`, `!=`, `<`, …).
    Compare {
        /// The comparison operator.
        op: CmpOp,
        /// The right-hand value.
        value: CmpValue,
    },
    /// Substring is present.
    Contains(String),
    /// Substring is absent.
    NotContains(String),
    /// Rust-syntax regular expression matches.
    Regex(String),
}

/// Where an `extract` pulls a value from (HTTP only).
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractSource {
    /// From the response body, optionally via a capture-group regex.
    Body {
        /// Probe name.
        target: String,
        /// Optional regex; capture group 1 (or the whole match) is extracted.
        regex: Option<String>,
    },
    /// From a named response header.
    Header {
        /// Probe name.
        target: String,
        /// Header name.
        name: String,
    },
}

/// A proof string attached to a finding. Every rule names an explicit source
/// (`.body`, `.response`, or `.header "<name>"`); an optional `regex` extracts
/// capture group 1 (or the whole match) from that source instead of taking it
/// whole.
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceKind {
    /// HTTP probe response body (`p.body` / `p.body regex '…'`).
    Body {
        /// Probe name.
        target: String,
        /// Optional regex; `None` takes the whole (truncated) body.
        pattern: Option<String>,
    },
    /// Probe response payload — HTTP body, DNS answers, or socket data
    /// (`p.response` / `p.response regex '…'`).
    Response {
        /// Probe name.
        target: String,
        /// Optional regex; `None` takes the whole (truncated) payload.
        pattern: Option<String>,
    },
    /// A named HTTP response header value (`p.header "X" ` / `p.header "X" regex '…'`).
    Header {
        /// Probe name.
        target: String,
        /// Header name (case-insensitive).
        name: String,
        /// Optional regex; `None` takes the whole header value.
        pattern: Option<String>,
    },
}

/// A comparison operator used by [`MatchPredicate::Compare`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CmpOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `>=`
    Ge,
}

/// The right-hand operand of a [`MatchPredicate::Compare`].
#[derive(Debug, Clone, PartialEq)]
pub enum CmpValue {
    /// A numeric literal (e.g. a status code or size).
    Number(u64),
    /// A string literal.
    String(String),
    /// A duration literal (e.g. `500ms`), compared against `response_time`.
    Duration(String),
}
