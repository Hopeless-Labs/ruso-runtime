use thiserror::Error;

use crate::contract::QualifiedMatch;
use crate::runtime::binary::BytecodeError;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("bytecode: {0}")]
    Bytecode(#[from] BytecodeError),
    #[error("unknown request or probe: {0}")]
    UnknownTarget(String),

    #[error("request {name} is not HTTP (dns/tcp probe)")]
    WrongProbeKind { name: String },

    #[error("match failed: {0}")]
    MatchFailed(String),

    #[error("assertion failed: {0}")]
    AssertFailed(String),

    #[error("extract failed for variable {name}: {reason}")]
    ExtractFailed { name: String, reason: String },

    #[error("flow control: {0}")]
    Flow(String),

    #[error("invalid duration: {0}")]
    InvalidDuration(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("{0}")]
    Other(String),
}

impl RuntimeError {
    pub fn match_failed(matcher: &QualifiedMatch, detail: impl Into<String>) -> Self {
        Self::MatchFailed(format!("{matcher:?}: {}", detail.into()))
    }

    pub fn assert_failed(matcher: &QualifiedMatch, detail: impl Into<String>) -> Self {
        Self::AssertFailed(format!("{matcher:?}: {}", detail.into()))
    }

    /// The complete error message, including every underlying cause.
    ///
    /// `thiserror`'s `Display` renders only this error's own message. For the
    /// wrapped HTTP and I/O variants the real reason — a rejected TLS
    /// certificate, a connection reset, a response body that failed to decode —
    /// lives in the [`source`](std::error::Error::source) chain and would
    /// otherwise be dropped, leaving an opaque `"http error: …"`. This walks
    /// that chain and joins it into one line so logs and scan reports carry the
    /// actual cause.
    pub fn full_message(&self) -> String {
        let mut message = self.to_string();
        let mut next = std::error::Error::source(self);
        while let Some(cause) = next {
            let cause_text = cause.to_string();
            // reqwest repeats its own Display as its first source; only append a
            // cause that adds information we don't already have.
            if !message.contains(&cause_text) {
                message.push_str(": ");
                message.push_str(&cause_text);
            }
            next = cause.source();
        }
        message
    }
}
