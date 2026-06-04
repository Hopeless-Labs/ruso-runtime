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
        join_source_chain(self)
    }
}

/// Render an error and its [`source`](std::error::Error::source) chain as a
/// single `"top: cause: root-cause"` line.
///
/// Only causes that add new text are appended: some errors (notably `reqwest`)
/// repeat their own `Display` as their first source, which would otherwise
/// duplicate a segment.
fn join_source_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut next = error.source();
    while let Some(cause) = next {
        let cause_text = cause.to_string();
        if !message.contains(&cause_text) {
            message.push_str(": ");
            message.push_str(&cause_text);
        }
        next = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::join_source_chain;
    use std::error::Error;
    use std::fmt;

    /// A minimal error whose source chain we control, for exercising
    /// [`join_source_chain`] without depending on reqwest/io internals.
    #[derive(Debug)]
    struct Layer {
        message: &'static str,
        source: Option<Box<Layer>>,
    }

    impl Layer {
        fn leaf(message: &'static str) -> Box<Self> {
            Box::new(Self {
                message,
                source: None,
            })
        }
        fn wrap(message: &'static str, source: Box<Layer>) -> Self {
            Self {
                message,
                source: Some(source),
            }
        }
    }

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.as_deref().map(|s| s as &(dyn Error + 'static))
        }
    }

    #[test]
    fn single_error_has_no_suffix() {
        let err = Layer {
            message: "io error",
            source: None,
        };
        assert_eq!(join_source_chain(&err), "io error");
    }

    #[test]
    fn joins_each_distinct_cause() {
        let err = Layer::wrap(
            "error sending request",
            Box::new(Layer::wrap(
                "client error (Connect)",
                Layer::leaf("invalid peer certificate"),
            )),
        );
        assert_eq!(
            join_source_chain(&err),
            "error sending request: client error (Connect): invalid peer certificate"
        );
    }

    #[test]
    fn skips_a_cause_already_present() {
        // reqwest repeats its top-level Display as its own first source.
        let err = Layer::wrap(
            "error sending request",
            Box::new(Layer::wrap(
                "error sending request",
                Layer::leaf("UnknownIssuer"),
            )),
        );
        assert_eq!(
            join_source_chain(&err),
            "error sending request: UnknownIssuer"
        );
    }
}
