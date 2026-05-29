use crate::contract::Severity;
use crate::runtime::spec::CheckMetadata;

#[derive(Debug, Clone)]
pub struct Finding {
    pub name: String,
    pub description: Option<String>,
    pub impact: Option<String>,
    pub severity: Severity,
    pub author: Option<String>,
    pub cve: Vec<String>,
    pub cwe: Vec<String>,
    pub references: Vec<String>,
    pub cvss: Vec<String>,
    pub cvss_score: Vec<String>,
    pub mitigation: Option<String>,
    pub evidence: Vec<String>,
}

impl Finding {
    /// Build the single finding for a script from its metadata block.
    pub fn from_metadata(metadata: &CheckMetadata, evidence: Vec<String>) -> Option<Self> {
        let name = metadata
            .name
            .clone()
            .or_else(|| metadata.report_title.clone())?;
        Some(Self {
            name,
            description: metadata.description.clone(),
            impact: metadata.impact.clone(),
            severity: metadata.severity.clone().unwrap_or(Severity::Info),
            author: metadata.author.clone(),
            cve: metadata.cve.clone(),
            cwe: metadata.cwe.clone(),
            references: metadata.references.clone(),
            cvss: metadata.cvss.clone(),
            cvss_score: metadata.cvss_score.clone(),
            mitigation: metadata.mitigation.clone(),
            evidence,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    /// Replace any prior finding — at most one per script execution.
    pub fn set_finding(&mut self, finding: Finding) {
        self.findings.clear();
        self.findings.push(finding);
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::Severity;
    use crate::runtime::spec::CheckMetadata;

    use super::Finding;

    #[test]
    fn from_metadata_requires_name_or_report_title() {
        let meta = CheckMetadata {
            name: Some("Check".into()),
            description: Some("desc".into()),
            severity: Some(Severity::Medium),
            ..Default::default()
        };
        let finding = Finding::from_metadata(&meta, vec!["proof".into()]).expect("finding");
        assert_eq!(finding.name, "Check");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.evidence, vec!["proof"]);
    }

    #[test]
    fn from_metadata_uses_report_title_fallback() {
        let meta = CheckMetadata {
            report_title: Some("Legacy title".into()),
            ..Default::default()
        };
        let finding = Finding::from_metadata(&meta, vec![]).expect("finding");
        assert_eq!(finding.name, "Legacy title");
        assert_eq!(finding.severity, Severity::Info);
    }
}
