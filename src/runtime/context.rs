use std::collections::HashMap;

use crate::runtime::report::{Finding, Report};
use crate::runtime::response::ProbeResponse;
use crate::runtime::session::ProbeSession;
use crate::runtime::spec::{CheckMetadata, ProgramSpec};

#[derive(Debug, Clone, PartialEq)]
pub enum VariableValue {
    String(String),
    List(Vec<String>),
}

impl VariableValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::List(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum LoopState {
    Repeat {
        remaining: u32,
    },
    ForEach {
        item: String,
        values: Vec<String>,
        index: usize,
        previous: Option<VariableValue>,
    },
}

#[derive(Debug)]
pub struct LoopFrame {
    pub state: LoopState,
    pub head_pc: usize,
    pub continue_pc: usize,
    pub end_pc: usize,
}

#[derive(Debug)]
pub struct Context {
    pub variables: HashMap<String, VariableValue>,
    pub responses: HashMap<String, ProbeResponse>,
    pub sessions: HashMap<String, ProbeSession>,
    pub metadata: CheckMetadata,
    pub report: Report,
    pub evidence: Vec<String>,
    pub retry_delay: Option<std::time::Duration>,
    pub failed: bool,
    pub matched: bool,
    /// When false, `stop` was hit — do not emit a finding even if matchers passed.
    pub emit_finding: bool,
    pub loop_stack: Vec<LoopFrame>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            variables: HashMap::new(),
            responses: HashMap::new(),
            sessions: HashMap::new(),
            metadata: CheckMetadata::default(),
            report: Report::default(),
            evidence: Vec::new(),
            retry_delay: None,
            failed: false,
            matched: true,
            emit_finding: true,
            loop_stack: Vec::new(),
        }
    }
}

impl Context {
    pub fn from_spec(spec: &ProgramSpec) -> Self {
        Self {
            metadata: spec.metadata.clone(),
            ..Default::default()
        }
    }

    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.variables
            .insert(name.into(), VariableValue::String(value.into()));
    }

    pub fn set_list_variable(&mut self, name: impl Into<String>, values: Vec<String>) {
        self.variables
            .insert(name.into(), VariableValue::List(values));
    }

    pub fn restore_or_remove_variable(
        &mut self,
        name: impl Into<String>,
        value: Option<VariableValue>,
    ) {
        let name = name.into();
        match value {
            Some(value) => {
                self.variables.insert(name, value);
            }
            None => {
                self.variables.remove(&name);
            }
        }
    }

    pub fn response(&self, name: &str) -> Option<&ProbeResponse> {
        self.responses.get(name)
    }

    pub fn store_response(&mut self, name: impl Into<String>, response: ProbeResponse) {
        self.responses.insert(name.into(), response);
    }

    pub fn alias_response(&mut self, from: &str, alias: impl Into<String>) {
        if let Some(response) = self.responses.get(from).cloned() {
            self.responses.insert(alias.into(), response);
        }
    }

    pub fn close_sessions(&mut self) {
        self.sessions.clear();
    }

    pub fn finalize_finding(&mut self) {
        if !self.matched || !self.emit_finding {
            return;
        }
        let evidence = std::mem::take(&mut self.evidence);
        if let Some(finding) = Finding::from_metadata(&self.metadata, evidence) {
            self.report.set_finding(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::Severity;

    use super::Context;

    #[test]
    fn finalize_emits_finding_when_matched() {
        let mut ctx = Context {
            matched: true,
            ..Context::default()
        };
        ctx.metadata.name = Some("Exposed .env".into());
        ctx.metadata.severity = Some(Severity::High);
        ctx.evidence.push("DB_PASSWORD=secret".into());
        ctx.finalize_finding();
        assert_eq!(ctx.report.findings.len(), 1);
        assert_eq!(ctx.report.findings[0].name, "Exposed .env");
        assert_eq!(ctx.report.findings[0].severity, Severity::High);
    }

    #[test]
    fn finalize_skips_when_match_chain_failed() {
        let mut ctx = Context {
            matched: false,
            ..Context::default()
        };
        ctx.metadata.name = Some("Should not emit".into());
        ctx.finalize_finding();
        assert!(ctx.report.findings.is_empty());
    }

    #[test]
    fn finalize_skips_after_stop() {
        let mut ctx = Context {
            matched: true,
            emit_finding: false,
            ..Context::default()
        };
        ctx.metadata.name = Some("Stopped".into());
        ctx.finalize_finding();
        assert!(ctx.report.findings.is_empty());
    }
}
