//! Human-readable bytecode disassembly.

use std::fmt::Write as _;

use crate::contract::{
    CmpOp, CmpValue, EvidenceKind, ExtractSource, FieldKind, MatchPredicate, QualifiedMatch,
};
use crate::runtime::binary;
use crate::runtime::bytecode::{BytecodeProgram, Instr};
use crate::runtime::spec::ProbeKind;

pub fn format_human(bytecode: &BytecodeProgram) -> String {
    let mut out = String::new();

    writeln!(out, ";; metadata").ok();
    format_metadata(&mut out, &bytecode.spec.metadata);
    writeln!(out).ok();

    writeln!(out, ";; probes ({})", bytecode.spec.probes.len()).ok();
    let mut probe_names: Vec<_> = bytecode.spec.probes.keys().collect();
    probe_names.sort();
    for name in probe_names {
        let kind = &bytecode.spec.probes[name];
        writeln!(out, ";;   probe {name}: {}", format_probe_kind(kind)).ok();
    }
    writeln!(out).ok();

    if !bytecode.strings.is_empty() {
        writeln!(out, ";; strings").ok();
        for (idx, value) in bytecode.strings.iter().enumerate() {
            writeln!(out, ";;   [{idx}] {value:?}").ok();
        }
        writeln!(out).ok();
    }

    if !bytecode.matchers.is_empty() {
        writeln!(out, ";; matchers").ok();
        for (idx, matcher) in bytecode.matchers.iter().enumerate() {
            writeln!(out, ";;   [{idx}] {}", format_matcher(matcher)).ok();
        }
        writeln!(out).ok();
    }

    if !bytecode.extracts.is_empty() {
        writeln!(out, ";; extracts").ok();
        for (idx, source) in bytecode.extracts.iter().enumerate() {
            writeln!(out, ";;   [{idx}] {}", format_extract(source)).ok();
        }
        writeln!(out).ok();
    }

    if !bytecode.evidence.is_empty() {
        writeln!(out, ";; evidence").ok();
        for (idx, kind) in bytecode.evidence.iter().enumerate() {
            writeln!(out, ";;   [{idx}] {}", format_evidence(kind)).ok();
        }
        writeln!(out).ok();
    }

    writeln!(out, ";; code ({} instructions)", bytecode.code.len()).ok();
    for (pc, instr) in bytecode.code.iter().enumerate() {
        writeln!(out, "  pc {pc:>3}: {}", format_instr(instr, bytecode)).ok();
    }

    out
}

fn format_metadata(out: &mut String, metadata: &crate::runtime::spec::CheckMetadata) {
    if let Some(name) = &metadata.name {
        writeln!(out, ";;   name: {name:?}").ok();
    }
    if let Some(description) = &metadata.description {
        writeln!(out, ";;   description: {description:?}").ok();
    }
    if let Some(impact) = &metadata.impact {
        writeln!(out, ";;   impact: {impact:?}").ok();
    }
    if let Some(severity) = &metadata.severity {
        writeln!(out, ";;   severity: {}", severity.as_str()).ok();
    }
    if let Some(author) = &metadata.author {
        writeln!(out, ";;   author: {author:?}").ok();
    }
    if let Some(title) = &metadata.report_title {
        writeln!(out, ";;   report: {title:?}").ok();
    }
    for cve in &metadata.cve {
        writeln!(out, ";;   cve: {cve:?}").ok();
    }
    for cwe in &metadata.cwe {
        writeln!(out, ";;   cwe: {cwe:?}").ok();
    }
    for reference in &metadata.references {
        writeln!(out, ";;   references: {reference:?}").ok();
    }
    for cvss in &metadata.cvss {
        writeln!(out, ";;   cvss: {cvss:?}").ok();
    }
    for score in &metadata.cvss_score {
        writeln!(out, ";;   cvss_score: {score:?}").ok();
    }
    for mitigation in &metadata.mitigation {
        writeln!(out, ";;   mitigation: {mitigation:?}").ok();
    }
}

fn format_probe_kind(kind: &ProbeKind) -> String {
    match kind {
        ProbeKind::Http(spec) => {
            format!("http {} {}", format_http_method(&spec.method), spec.path)
        }
        ProbeKind::Dns(spec) => format_socket_probe("dns", spec),
        ProbeKind::Tcp(spec) => format_socket_probe("tcp", spec),
        ProbeKind::Udp(spec) => format_socket_probe("udp", spec),
    }
}

fn format_socket_probe(label: &str, spec: &crate::runtime::spec::SocketProbeSpec) -> String {
    let mut line = format!("{label} host={:?}", spec.host);
    if let Some(port) = spec.port {
        line.push_str(&format!(" port={port}"));
    }
    if let Some(payload) = &spec.payload {
        let is_text = payload.iter().all(|b| {
            b.is_ascii_graphic() || *b == b' ' || *b == b'\r' || *b == b'\n' || *b == b'\t'
        });
        let shown = if is_text {
            // Decode lossy as text — `format!("{:?}", Vec<u8>)` would
            // print "[80, 73, 78, 71]" instead of "\"PING\"".
            let text = String::from_utf8_lossy(payload);
            format!("{text:?}")
        } else {
            format!("0x{}", crate::runtime::binary::bytes_to_hex(payload))
        };
        line.push_str(&format!(" payload={shown}"));
    }
    if label == "dns" && spec.is_dns_resolver_mode() {
        line.push_str(" (resolver)");
    }
    line
}

fn format_http_method(method: &crate::contract::HttpMethod) -> &'static str {
    use crate::contract::HttpMethod;
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
    }
}

fn format_matcher(matcher: &QualifiedMatch) -> String {
    let field = match &matcher.field.kind {
        FieldKind::Status => "status".to_string(),
        FieldKind::Body => "body".to_string(),
        FieldKind::Header(name) => format!("header({name:?})"),
        FieldKind::ResponseTime => "response_time".to_string(),
        FieldKind::ResponseSize => "response_size".to_string(),
        FieldKind::Answer => "answer".to_string(),
        FieldKind::Banner => "banner".to_string(),
        FieldKind::Response => "response".to_string(),
    };
    format!(
        "{}.{} {}",
        matcher.field.target,
        field,
        format_predicate(&matcher.predicate)
    )
}

fn format_predicate(predicate: &MatchPredicate) -> String {
    match predicate {
        MatchPredicate::Compare { op, value } => {
            format!("{} {}", format_cmp_op(*op), format_cmp_value(value))
        }
        MatchPredicate::Contains(text) => format!("contains {text:?}"),
        MatchPredicate::NotContains(text) => format!("not_contains {text:?}"),
        MatchPredicate::Regex(pattern) => format!("regex {pattern:?}"),
    }
}

fn format_cmp_op(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
        CmpOp::Lt => "<",
        CmpOp::Gt => ">",
        CmpOp::Le => "<=",
        CmpOp::Ge => ">=",
    }
}

fn format_cmp_value(value: &CmpValue) -> String {
    match value {
        CmpValue::Number(n) => n.to_string(),
        CmpValue::String(s) => format!("{s:?}"),
        CmpValue::Duration(d) => d.clone(),
    }
}

fn format_extract(source: &ExtractSource) -> String {
    match source {
        ExtractSource::Body { target, regex } => match regex {
            Some(pattern) => format!("body from {target} regex {pattern:?}"),
            None => format!("body from {target}"),
        },
        ExtractSource::Header { target, name } => {
            format!("header {name:?} from {target}")
        }
    }
}

fn format_evidence(kind: &EvidenceKind) -> String {
    match kind {
        EvidenceKind::BodyRef(target) => format!("body {target}"),
        EvidenceKind::ResponseRef(target) => format!("response {target}"),
        EvidenceKind::Regex { target, pattern } => format!("regex {target} {pattern:?}"),
    }
}

fn format_instr(instr: &Instr, bytecode: &BytecodeProgram) -> String {
    let str_at = |idx: u32| -> String {
        bytecode
            .strings
            .get(idx as usize)
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| format!("#{idx}?"))
    };
    // Use `.get()` rather than direct slicing so corrupt-but-decodable
    // bytecode (start/len pointing past the string pool) cannot panic the
    // disassembler — important because `ruso disasm` is reachable from
    // untrusted `.bc` files.
    let string_span = |start: u32, len: u16| -> String {
        let start = start as usize;
        let end = start.saturating_add(len as usize);
        match bytecode.strings.get(start..end) {
            Some(slice) => slice
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            None => format!("<oob {start}..{end}>"),
        }
    };

    match instr {
        Instr::Set { name, value } => {
            format!("Set name={} value={}", str_at(*name), str_at(*value))
        }
        Instr::SetList { name, start, len } => {
            format!(
                "SetList name={} values=[{}]",
                str_at(*name),
                string_span(*start, *len)
            )
        }
        Instr::Send { probe, payload } => {
            if let Some(id) = payload {
                format!(
                    "Send {} payload=[{}]",
                    str_at(*probe),
                    bytecode
                        .payloads
                        .get(*id as usize)
                        .map(|p| binary::bytes_to_hex(p))
                        .unwrap_or_else(|| format!("#{id}?"))
                )
            } else {
                format!("Send {}", str_at(*probe))
            }
        }
        Instr::Match(matcher) => format!("Match [{}]", matcher),
        Instr::MatchAll { start, len } => format!("MatchAll [{start}..{}]", start + *len as u32),
        Instr::MatchAny { start, len } => format!("MatchAny [{start}..{}]", start + *len as u32),
        Instr::Assert(matcher) => format!("Assert [{}]", matcher),
        Instr::Extract { name, source } => {
            format!("Extract name={} source=[{}]", str_at(*name), source)
        }
        Instr::IfMatch { matcher, else_pc } => {
            format!("IfMatch [{}] else_pc={else_pc}", matcher)
        }
        Instr::Repeat { count, end_pc } => format!("Repeat count={count} end_pc={end_pc}"),
        Instr::ForList {
            item,
            start,
            len,
            end_pc,
        } => format!(
            "ForList item={} values=[{}] end_pc={end_pc}",
            str_at(*item),
            string_span(*start, *len)
        ),
        Instr::ForVar { item, list, end_pc } => {
            format!(
                "ForVar item={} list={} end_pc={end_pc}",
                str_at(*item),
                str_at(*list)
            )
        }
        Instr::LoopBack => "LoopBack".into(),
        Instr::Break => "Break".into(),
        Instr::Save { from, to } => {
            format!("Save {} as {}", str_at(*from), str_at(*to))
        }
        Instr::Evidence(kind) => format!("Evidence [{}]", kind),
        Instr::Retry { probe, count } => {
            format!("Retry {} count={count}", str_at(*probe))
        }
        Instr::RetryDelay(value) => format!("RetryDelay {}", str_at(*value)),
        Instr::Sleep(value) => format!("Sleep {}", str_at(*value)),
        Instr::Stop => "Stop".into(),
        Instr::Fail => "Fail".into(),
        Instr::Continue => "Continue".into(),
        Instr::Exit => "Exit".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::bytecode::Instr;
    use crate::runtime::spec::{CheckMetadata, ProgramSpec};

    fn empty_bytecode() -> BytecodeProgram {
        BytecodeProgram {
            spec: ProgramSpec {
                probes: Default::default(),
                metadata: CheckMetadata::default(),
            },
            code: vec![],
            strings: vec![],
            payloads: vec![],
            matchers: vec![],
            extracts: vec![],
            evidence: vec![],
        }
    }

    #[test]
    fn out_of_bounds_string_span_does_not_panic() {
        // Crafted (corrupt) bytecode where ForList claims a string span
        // beyond the actual pool. Pre-fix this would panic in the
        // disassembler — now it should render a sentinel.
        let bytecode = BytecodeProgram {
            code: vec![Instr::ForList {
                item: 99,
                start: 99,
                len: 5,
                end_pc: 0,
            }],
            ..empty_bytecode()
        };
        let out = format_human(&bytecode);
        assert!(out.contains("<oob"), "expected oob sentinel, got:\n{out}");
    }
}
