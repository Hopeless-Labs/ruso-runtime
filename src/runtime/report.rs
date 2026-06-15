use crate::contract::Severity;
use crate::runtime::spec::CheckMetadata;

/// A single positive result: the check's metadata resolved into a concrete
/// finding, plus the evidence captured during the run. Built from
/// [`CheckMetadata`] via [`Finding::from_metadata`].
#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding title (from metadata `name`).
    pub name: String,
    /// What the check found.
    pub description: Option<String>,
    /// The risk this finding represents.
    pub impact: Option<String>,
    /// Severity (defaults to `Info` when the check set none).
    pub severity: Severity,
    /// Check author.
    pub author: Option<String>,
    /// Associated CVE identifiers.
    pub cve: Vec<String>,
    /// Associated CWE identifiers.
    pub cwe: Vec<String>,
    /// Reference URLs.
    pub references: Vec<String>,
    /// CVSS vector strings.
    pub cvss: Vec<String>,
    /// CVSS numeric scores.
    pub cvss_score: Vec<String>,
    /// Remediation guidance.
    pub mitigation: Option<String>,
    /// Proof strings captured by `evidence` rules.
    pub evidence: Vec<String>,
}

impl Finding {
    /// Build the single finding for a script from its metadata block.
    pub fn from_metadata(metadata: &CheckMetadata, evidence: Vec<String>) -> Option<Self> {
        let name = metadata.name.clone()?;
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

/// A run's findings. At most one finding is produced per script execution, so
/// this holds zero or one entry.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// The findings emitted (zero or one).
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
    fn from_metadata_requires_name() {
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
    fn from_metadata_without_name_is_none() {
        let meta = CheckMetadata {
            description: Some("desc".into()),
            ..Default::default()
        };
        assert!(Finding::from_metadata(&meta, vec![]).is_none());
    }
}
