use std::collections::HashMap;

use crate::runtime::report::{Finding, Report};
use crate::runtime::response::ProbeResponse;
use crate::runtime::session::ProbeSession;
use crate::runtime::spec::{CheckMetadata, ProgramSpec};

#[derive(Debug, Default)]
pub struct LoopFrame {
    pub remaining: u32,
    pub head_pc: usize,
    pub end_pc: usize,
}

#[derive(Debug, Default)]
pub struct Context {
    pub variables: HashMap<String, String>,
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

impl Context {
    pub fn from_spec(spec: &ProgramSpec) -> Self {
        Self {
            metadata: spec.metadata.clone(),
            matched: true,
            emit_finding: true,
            ..Default::default()
        }
    }

    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.variables.insert(name.into(), value.into());
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
        let mut ctx = Context::default();
        ctx.matched = true;
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
        let mut ctx = Context::default();
        ctx.matched = false;
        ctx.metadata.name = Some("Should not emit".into());
        ctx.finalize_finding();
        assert!(ctx.report.findings.is_empty());
    }

    #[test]
    fn finalize_skips_after_stop() {
        let mut ctx = Context::default();
        ctx.matched = true;
        ctx.emit_finding = false;
        ctx.metadata.name = Some("Stopped".into());
        ctx.finalize_finding();
        assert!(ctx.report.findings.is_empty());
    }
}
