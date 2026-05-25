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
}
