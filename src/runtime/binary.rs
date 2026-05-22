//! Binary serialization of `BytecodeProgram` (magic `RUSO`, version 1).

use std::collections::HashMap;

use thiserror::Error;

use crate::runtime::bytecode::{BytecodeProgram, Instr};
use crate::runtime::spec::{CheckMetadata, HttpRequestSpec, ProbeKind, ProgramSpec};
use crate::contract::{
    BodyValue, CmpOp, CmpValue, EvidenceKind, ExtractSource, FieldKind, HttpMethod,
    InlinePart, InlinePartBody, MatchPredicate, ObjectBody, QualifiedField, QualifiedMatch,
    Severity,
};

pub const MAGIC: &[u8; 4] = b"RUSO";
pub const VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum BytecodeError {
    #[error("bytecode too short")]
    TooShort,
    #[error("invalid magic")]
    BadMagic,
    #[error("unsupported version {0}")]
    BadVersion(u8),
    #[error("corrupt bytecode: {0}")]
    Corrupt(&'static str),
    #[error("invalid hex: {0}")]
    InvalidHex(String),
}

pub fn encode(program: &BytecodeProgram) -> Vec<u8> {
    let mut w = Writer::default();
    w.bytes(MAGIC);
    w.u8(VERSION);
    write_metadata(&mut w, &program.spec.metadata);
    write_probes(&mut w, &program.spec.probes);
    write_strings(&mut w, &program.strings);
    write_payloads(&mut w, &program.payloads);
    write_matchers(&mut w, &program.matchers);
    write_extracts(&mut w, &program.extracts);
    write_evidence(&mut w, &program.evidence);
    write_code(&mut w, &program.code);
    w.0
}

pub fn decode(bytes: &[u8]) -> Result<BytecodeProgram, BytecodeError> {
    let mut r = Reader::new(bytes);
    r.consume_magic()?;
    let version = r.u8()?;
    if version != VERSION {
        return Err(BytecodeError::BadVersion(version));
    }
    let metadata = read_metadata(&mut r)?;
    let probes = read_probes(&mut r)?;
    let strings = read_strings(&mut r)?;
    let payloads = read_payloads(&mut r)?;
    let matchers = read_matchers(&mut r)?;
    let extracts = read_extracts(&mut r)?;
    let evidence = read_evidence(&mut r)?;
    let code = read_code(&mut r)?;
    if r.remaining() != 0 {
        return Err(BytecodeError::Corrupt("trailing bytes"));
    }
    Ok(BytecodeProgram {
        spec: ProgramSpec { probes, metadata },
        code,
        strings,
        payloads,
        matchers,
        extracts,
        evidence,
    })
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn bytes_to_hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (offset, chunk) in bytes.chunks(16).enumerate() {
        let off = offset * 16;
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let pad = if chunk.len() < 16 {
            "   ".repeat(16 - chunk.len())
        } else {
            String::new()
        };
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{off:08x}: {hex}{pad}  |{ascii}|\n"));
    }
    out
}

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, BytecodeError> {
    let hex: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if hex.len() % 2 != 0 {
        return Err(BytecodeError::InvalidHex("odd length".into()));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let pair: String = chars[i..i + 2].iter().collect();
        let byte = u8::from_str_radix(&pair, 16)
            .map_err(|err| BytecodeError::InvalidHex(err.to_string()))?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}

/// Hex string or `@path` to raw bytecode file.
pub fn load_bytecode_input(input: &str) -> Result<Vec<u8>, BytecodeError> {
    let trimmed = input.trim();
    if let Some(path) = trimmed.strip_prefix('@') {
        std::fs::read(path).map_err(|err| BytecodeError::InvalidHex(err.to_string()))
    } else {
        hex_to_bytes(trimmed)
    }
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }

    fn str(&mut self, s: &str) {
        let b = s.as_bytes();
        self.u32(b.len() as u32);
        self.bytes(b);
    }

    fn opt_str(&mut self, value: &Option<String>) {
        match value {
            Some(s) => {
                self.u8(1);
                self.str(s);
            }
            None => self.u8(0),
        }
    }

    fn opt_bytes(&mut self, value: &Option<Vec<u8>>) {
        match value {
            Some(data) => {
                self.u8(1);
                self.u32(data.len() as u32);
                self.bytes(data);
            }
            None => self.u8(0),
        }
    }

    fn opt_u16(&mut self, value: Option<u16>) {
        match value {
            Some(v) => {
                self.u8(1);
                self.u16(v);
            }
            None => self.u8(0),
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn consume_magic(&mut self) -> Result<(), BytecodeError> {
        let magic = self.need(4)?;
        if magic != MAGIC {
            return Err(BytecodeError::BadMagic);
        }
        Ok(())
    }

    fn need(&mut self, n: usize) -> Result<&'a [u8], BytecodeError> {
        if self.pos + n > self.data.len() {
            return Err(BytecodeError::Corrupt("unexpected end"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BytecodeError> {
        Ok(self.need(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BytecodeError> {
        Ok(u16::from_le_bytes(self.need(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, BytecodeError> {
        Ok(u32::from_le_bytes(self.need(4)?.try_into().unwrap()))
    }

    fn str(&mut self) -> Result<String, BytecodeError> {
        let len = self.u32()? as usize;
        let bytes = self.need(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| BytecodeError::Corrupt("utf8"))
    }

    fn opt_str(&mut self) -> Result<Option<String>, BytecodeError> {
        if self.u8()? == 0 {
            Ok(None)
        } else {
            Ok(Some(self.str()?))
        }
    }

    fn opt_bytes(&mut self) -> Result<Option<Vec<u8>>, BytecodeError> {
        if self.u8()? == 0 {
            Ok(None)
        } else {
            let len = self.u32()? as usize;
            Ok(Some(self.need(len)?.to_vec()))
        }
    }

    fn opt_u16(&mut self) -> Result<Option<u16>, BytecodeError> {
        if self.u8()? == 0 {
            Ok(None)
        } else {
            Ok(Some(self.u16()?))
        }
    }
}

fn write_metadata(w: &mut Writer, metadata: &CheckMetadata) {
    w.opt_str(&metadata.name);
    w.opt_str(&metadata.description);
    w.opt_str(&metadata.impact);
    match &metadata.severity {
        Some(s) => {
            w.u8(1);
            w.u8(severity_tag(s));
        }
        None => w.u8(0),
    }
    w.opt_str(&metadata.author);
    w.opt_str(&metadata.report_title);
    write_strings(w, &metadata.cve);
    write_strings(w, &metadata.cwe);
    write_strings(w, &metadata.references);
    write_strings(w, &metadata.cvss);
    write_strings(w, &metadata.cvss_score);
    write_strings(w, &metadata.mitigation);
}

fn read_metadata(r: &mut Reader<'_>) -> Result<CheckMetadata, BytecodeError> {
    Ok(CheckMetadata {
        name: r.opt_str()?,
        description: r.opt_str()?,
        impact: r.opt_str()?,
        severity: if r.u8()? == 0 {
            None
        } else {
            Some(read_severity(r)?)
        },
        author: r.opt_str()?,
        report_title: r.opt_str()?,
        cve: read_strings(r)?,
        cwe: read_strings(r)?,
        references: read_strings(r)?,
        cvss: read_strings(r)?,
        cvss_score: read_strings(r)?,
        mitigation: read_strings(r)?,
    })
}

fn severity_tag(s: &Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
        Severity::Info => 4,
    }
}

fn read_severity(r: &mut Reader<'_>) -> Result<Severity, BytecodeError> {
    Ok(match r.u8()? {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        3 => Severity::Critical,
        _ => Severity::Info,
    })
}

fn write_probes(w: &mut Writer, probes: &HashMap<String, ProbeKind>) {
    let mut names: Vec<_> = probes.keys().cloned().collect();
    names.sort();
    w.u32(names.len() as u32);
    for name in names {
        w.str(&name);
        write_probe_kind(w, probes.get(&name).expect("sorted key"));
    }
}

fn read_probes(r: &mut Reader<'_>) -> Result<HashMap<String, ProbeKind>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut probes = HashMap::with_capacity(count);
    for _ in 0..count {
        let name = r.str()?;
        let kind = read_probe_kind(r)?;
        probes.insert(name, kind);
    }
    Ok(probes)
}

fn write_probe_kind(w: &mut Writer, kind: &ProbeKind) {
    match kind {
        ProbeKind::Http(spec) => {
            w.u8(0);
            write_http_spec(w, spec);
        }
        ProbeKind::Dns(spec) => {
            w.u8(1);
            write_socket_probe(w, spec);
        }
        ProbeKind::Tcp(spec) => {
            w.u8(2);
            write_socket_probe(w, spec);
        }
        ProbeKind::Udp(spec) => {
            w.u8(3);
            write_socket_probe(w, spec);
        }
    }
}

fn write_socket_probe(w: &mut Writer, spec: &crate::runtime::spec::SocketProbeSpec) {
    w.str(&spec.host);
    w.opt_u16(spec.port);
    w.opt_bytes(&spec.payload);
    w.u8(u8::from(spec.tls));
    w.u8(u8::from(spec.session));
    w.u32(spec.read_max);
    w.u32(spec.read_idle_ms);
}

fn read_socket_probe(r: &mut Reader<'_>) -> Result<crate::runtime::spec::SocketProbeSpec, BytecodeError> {
    Ok(crate::runtime::spec::SocketProbeSpec {
        host: r.str()?,
        port: r.opt_u16()?,
        payload: r.opt_bytes()?,
        tls: r.u8()? != 0,
        session: r.u8()? != 0,
        read_max: r.u32()?,
        read_idle_ms: r.u32()?,
    })
}

fn read_probe_kind(r: &mut Reader<'_>) -> Result<ProbeKind, BytecodeError> {
    Ok(match r.u8()? {
        0 => ProbeKind::Http(read_http_spec(r)?),
        1 => ProbeKind::Dns(read_socket_probe(r)?),
        2 => ProbeKind::Tcp(read_socket_probe(r)?),
        3 => ProbeKind::Udp(read_socket_probe(r)?),
        _ => return Err(BytecodeError::Corrupt("probe kind")),
    })
}

fn write_http_spec(w: &mut Writer, spec: &HttpRequestSpec) {
    w.u8(http_method_tag(&spec.method));
    w.str(&spec.path);
    w.opt_str(&spec.timeout);
    write_opt_bool(w, &spec.follow_redirect);
    write_opt_bool(w, &spec.verify_ssl);
    w.opt_str(&spec.proxy);
    w.opt_str(&spec.user_agent);
    write_header_list(w, &spec.headers);
    write_header_list(w, &spec.cookies);
    write_header_list(w, &spec.queries);
    write_opt_object(w, &spec.data_body);
    write_opt_object(w, &spec.json_body);
    w.opt_str(&spec.raw_body);
    w.opt_str(&spec.body_bytes);
    write_opt_object(w, &spec.multipart_body);
}

fn read_http_spec(r: &mut Reader<'_>) -> Result<HttpRequestSpec, BytecodeError> {
    Ok(HttpRequestSpec {
        method: read_http_method(r)?,
        path: r.str()?,
        timeout: r.opt_str()?,
        follow_redirect: read_opt_bool(r)?,
        verify_ssl: read_opt_bool(r)?,
        proxy: r.opt_str()?,
        user_agent: r.opt_str()?,
        headers: read_header_list(r)?,
        cookies: read_header_list(r)?,
        queries: read_header_list(r)?,
        data_body: read_opt_object(r)?,
        json_body: read_opt_object(r)?,
        raw_body: r.opt_str()?,
        body_bytes: r.opt_str()?,
        multipart_body: read_opt_object(r)?,
    })
}

fn http_method_tag(m: &HttpMethod) -> u8 {
    match m {
        HttpMethod::Get => 0,
        HttpMethod::Post => 1,
        HttpMethod::Put => 2,
        HttpMethod::Patch => 3,
        HttpMethod::Delete => 4,
    }
}

fn read_http_method(r: &mut Reader<'_>) -> Result<HttpMethod, BytecodeError> {
    Ok(match r.u8()? {
        1 => HttpMethod::Post,
        2 => HttpMethod::Put,
        3 => HttpMethod::Patch,
        4 => HttpMethod::Delete,
        _ => HttpMethod::Get,
    })
}

fn write_opt_bool(w: &mut Writer, value: &Option<bool>) {
    match value {
        Some(v) => {
            w.u8(1);
            w.u8(u8::from(*v));
        }
        None => w.u8(0),
    }
}

fn read_opt_bool(r: &mut Reader<'_>) -> Result<Option<bool>, BytecodeError> {
    if r.u8()? == 0 {
        Ok(None)
    } else {
        Ok(Some(r.u8()? != 0))
    }
}

fn write_header_list(w: &mut Writer, pairs: &[(String, String)]) {
    w.u32(pairs.len() as u32);
    for (k, v) in pairs {
        w.str(k);
        w.str(v);
    }
}

fn read_header_list(r: &mut Reader<'_>) -> Result<Vec<(String, String)>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        pairs.push((r.str()?, r.str()?));
    }
    Ok(pairs)
}

fn write_opt_object(w: &mut Writer, body: &Option<ObjectBody>) {
    match body {
        Some(obj) => {
            w.u8(1);
            write_object(w, obj);
        }
        None => w.u8(0),
    }
}

fn read_opt_object(r: &mut Reader<'_>) -> Result<Option<ObjectBody>, BytecodeError> {
    if r.u8()? == 0 {
        Ok(None)
    } else {
        Ok(Some(read_object(r)?))
    }
}

fn write_object(w: &mut Writer, obj: &ObjectBody) {
    w.u32(obj.pairs.len() as u32);
    for (key, value) in &obj.pairs {
        w.str(key);
        write_body_value(w, value);
    }
}

fn read_object(r: &mut Reader<'_>) -> Result<ObjectBody, BytecodeError> {
    let count = r.u32()? as usize;
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        pairs.push((r.str()?, read_body_value(r)?));
    }
    Ok(ObjectBody { pairs })
}

fn write_body_value(w: &mut Writer, value: &BodyValue) {
    match value {
        BodyValue::String(s) => {
            w.u8(0);
            w.str(s);
        }
        BodyValue::Interpolation(s) => {
            w.u8(1);
            w.str(s);
        }
        BodyValue::Object(obj) => {
            w.u8(2);
            write_object(w, obj);
        }
        BodyValue::Bytes(hex) => {
            w.u8(3);
            w.str(hex);
        }
        BodyValue::Part(part) => {
            w.u8(4);
            w.opt_str(&part.filename);
            match &part.body {
                InlinePartBody::Text(t) => {
                    w.u8(0);
                    w.str(t);
                }
                InlinePartBody::Bytes(b) => {
                    w.u8(1);
                    w.str(b);
                }
            }
        }
    }
}

fn read_body_value(r: &mut Reader<'_>) -> Result<BodyValue, BytecodeError> {
    Ok(match r.u8()? {
        0 => BodyValue::String(r.str()?),
        1 => BodyValue::Interpolation(r.str()?),
        2 => BodyValue::Object(read_object(r)?),
        3 => BodyValue::Bytes(r.str()?),
        4 => BodyValue::Part(InlinePart {
            filename: r.opt_str()?,
            body: match r.u8()? {
                1 => InlinePartBody::Bytes(r.str()?),
                _ => InlinePartBody::Text(r.str()?),
            },
        }),
        _ => return Err(BytecodeError::Corrupt("body value")),
    })
}

fn write_strings(w: &mut Writer, strings: &[String]) {
    w.u32(strings.len() as u32);
    for s in strings {
        w.str(s);
    }
}

fn read_strings(r: &mut Reader<'_>) -> Result<Vec<String>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut strings = Vec::with_capacity(count);
    for _ in 0..count {
        strings.push(r.str()?);
    }
    Ok(strings)
}

fn write_payloads(w: &mut Writer, payloads: &[Vec<u8>]) {
    w.u32(payloads.len() as u32);
    for data in payloads {
        w.u32(data.len() as u32);
        w.bytes(data);
    }
}

fn read_payloads(r: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.u32()? as usize;
        payloads.push(r.need(len)?.to_vec());
    }
    Ok(payloads)
}

fn write_matchers(w: &mut Writer, matchers: &[QualifiedMatch]) {
    w.u32(matchers.len() as u32);
    for m in matchers {
        write_matcher(w, m);
    }
}

fn read_matchers(r: &mut Reader<'_>) -> Result<Vec<QualifiedMatch>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut matchers = Vec::with_capacity(count);
    for _ in 0..count {
        matchers.push(read_matcher(r)?);
    }
    Ok(matchers)
}

fn write_matcher(w: &mut Writer, m: &QualifiedMatch) {
    w.str(&m.field.target);
    write_field_kind(w, &m.field.kind);
    write_predicate(w, &m.predicate);
}

fn read_matcher(r: &mut Reader<'_>) -> Result<QualifiedMatch, BytecodeError> {
    Ok(QualifiedMatch {
        field: QualifiedField {
            target: r.str()?,
            kind: read_field_kind(r)?,
        },
        predicate: read_predicate(r)?,
    })
}

fn write_field_kind(w: &mut Writer, kind: &FieldKind) {
    match kind {
        FieldKind::Status => w.u8(0),
        FieldKind::Body => w.u8(1),
        FieldKind::Header(name) => {
            w.u8(2);
            w.str(name);
        }
        FieldKind::ResponseTime => w.u8(3),
        FieldKind::ResponseSize => w.u8(4),
        FieldKind::Answer => w.u8(5),
        FieldKind::Banner => w.u8(6),
        FieldKind::Response => w.u8(7),
    }
}

fn read_field_kind(r: &mut Reader<'_>) -> Result<FieldKind, BytecodeError> {
    Ok(match r.u8()? {
        0 => FieldKind::Status,
        1 => FieldKind::Body,
        2 => FieldKind::Header(r.str()?),
        3 => FieldKind::ResponseTime,
        4 => FieldKind::ResponseSize,
        5 => FieldKind::Answer,
        6 => FieldKind::Banner,
        7 => FieldKind::Response,
        _ => return Err(BytecodeError::Corrupt("field kind")),
    })
}

fn write_predicate(w: &mut Writer, p: &MatchPredicate) {
    match p {
        MatchPredicate::Compare { op, value } => {
            w.u8(0);
            w.u8(cmp_op_tag(*op));
            write_cmp_value(w, value);
        }
        MatchPredicate::Contains(s) => {
            w.u8(1);
            w.str(s);
        }
        MatchPredicate::NotContains(s) => {
            w.u8(2);
            w.str(s);
        }
        MatchPredicate::Regex(s) => {
            w.u8(3);
            w.str(s);
        }
    }
}

fn read_predicate(r: &mut Reader<'_>) -> Result<MatchPredicate, BytecodeError> {
    Ok(match r.u8()? {
        0 => MatchPredicate::Compare {
            op: read_cmp_op(r)?,
            value: read_cmp_value(r)?,
        },
        1 => MatchPredicate::Contains(r.str()?),
        2 => MatchPredicate::NotContains(r.str()?),
        3 => MatchPredicate::Regex(r.str()?),
        _ => return Err(BytecodeError::Corrupt("predicate")),
    })
}

fn cmp_op_tag(op: CmpOp) -> u8 {
    match op {
        CmpOp::Eq => 0,
        CmpOp::Ne => 1,
        CmpOp::Lt => 2,
        CmpOp::Gt => 3,
        CmpOp::Le => 4,
        CmpOp::Ge => 5,
    }
}

fn read_cmp_op(r: &mut Reader<'_>) -> Result<CmpOp, BytecodeError> {
    Ok(match r.u8()? {
        1 => CmpOp::Ne,
        2 => CmpOp::Lt,
        3 => CmpOp::Gt,
        4 => CmpOp::Le,
        5 => CmpOp::Ge,
        _ => CmpOp::Eq,
    })
}

fn write_cmp_value(w: &mut Writer, value: &CmpValue) {
    match value {
        CmpValue::Number(n) => {
            w.u8(0);
            w.u32(*n as u32);
        }
        CmpValue::String(s) => {
            w.u8(1);
            w.str(s);
        }
        CmpValue::Duration(d) => {
            w.u8(2);
            w.str(d);
        }
    }
}

fn read_cmp_value(r: &mut Reader<'_>) -> Result<CmpValue, BytecodeError> {
    Ok(match r.u8()? {
        1 => CmpValue::String(r.str()?),
        2 => CmpValue::Duration(r.str()?),
        _ => CmpValue::Number(r.u32()? as u64),
    })
}

fn write_extracts(w: &mut Writer, extracts: &[ExtractSource]) {
    w.u32(extracts.len() as u32);
    for e in extracts {
        write_extract(w, e);
    }
}

fn read_extracts(r: &mut Reader<'_>) -> Result<Vec<ExtractSource>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut extracts = Vec::with_capacity(count);
    for _ in 0..count {
        extracts.push(read_extract(r)?);
    }
    Ok(extracts)
}

fn write_extract(w: &mut Writer, e: &ExtractSource) {
    match e {
        ExtractSource::Body { target, regex } => {
            w.u8(0);
            w.str(target);
            w.opt_str(regex);
        }
        ExtractSource::Header { target, name } => {
            w.u8(1);
            w.str(target);
            w.str(name);
        }
    }
}

fn read_extract(r: &mut Reader<'_>) -> Result<ExtractSource, BytecodeError> {
    Ok(match r.u8()? {
        0 => ExtractSource::Body {
            target: r.str()?,
            regex: r.opt_str()?,
        },
        1 => ExtractSource::Header {
            target: r.str()?,
            name: r.str()?,
        },
        _ => return Err(BytecodeError::Corrupt("extract")),
    })
}

fn write_evidence(w: &mut Writer, kinds: &[EvidenceKind]) {
    w.u32(kinds.len() as u32);
    for k in kinds {
        write_evidence_kind(w, k);
    }
}

fn read_evidence(r: &mut Reader<'_>) -> Result<Vec<EvidenceKind>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut kinds = Vec::with_capacity(count);
    for _ in 0..count {
        kinds.push(read_evidence_kind(r)?);
    }
    Ok(kinds)
}

fn write_evidence_kind(w: &mut Writer, k: &EvidenceKind) {
    match k {
        EvidenceKind::BodyRef(target) => {
            w.u8(0);
            w.str(target);
        }
        EvidenceKind::ResponseRef(target) => {
            w.u8(2);
            w.str(target);
        }
        EvidenceKind::Regex { target, pattern } => {
            w.u8(1);
            w.str(target);
            w.str(pattern);
        }
    }
}

fn read_evidence_kind(r: &mut Reader<'_>) -> Result<EvidenceKind, BytecodeError> {
    Ok(match r.u8()? {
        0 => EvidenceKind::BodyRef(r.str()?),
        1 => EvidenceKind::Regex {
            target: r.str()?,
            pattern: r.str()?,
        },
        2 => EvidenceKind::ResponseRef(r.str()?),
        _ => return Err(BytecodeError::Corrupt("evidence")),
    })
}

const OP_SET: u8 = 1;
const OP_SEND: u8 = 2;
const OP_MATCH: u8 = 3;
const OP_MATCH_ALL: u8 = 4;
const OP_MATCH_ANY: u8 = 5;
const OP_ASSERT: u8 = 6;
const OP_EXTRACT: u8 = 7;
const OP_IF_MATCH: u8 = 8;
const OP_SAVE: u8 = 9;
const OP_EVIDENCE: u8 = 10;
const OP_RETRY: u8 = 11;
const OP_RETRY_DELAY: u8 = 12;
const OP_SLEEP: u8 = 13;
const OP_STOP: u8 = 14;
const OP_FAIL: u8 = 15;
const OP_CONTINUE: u8 = 16;
const OP_EXIT: u8 = 17;
const OP_REPEAT: u8 = 18;
const OP_LOOP_BACK: u8 = 19;
const OP_BREAK: u8 = 20;

fn write_code(w: &mut Writer, code: &[Instr]) {
    w.u32(code.len() as u32);
    for instr in code {
        write_instr(w, instr);
    }
}

fn read_code(r: &mut Reader<'_>) -> Result<Vec<Instr>, BytecodeError> {
    let count = r.u32()? as usize;
    let mut code = Vec::with_capacity(count);
    for _ in 0..count {
        code.push(read_instr(r)?);
    }
    Ok(code)
}

fn write_instr(w: &mut Writer, instr: &Instr) {
    match instr {
        Instr::Set { name, value } => {
            w.u8(OP_SET);
            w.u32(*name);
            w.u32(*value);
        }
        Instr::Send { probe, payload } => {
            w.u8(OP_SEND);
            w.u32(*probe);
            match payload {
                Some(id) => {
                    w.u8(1);
                    w.u32(*id);
                }
                None => w.u8(0),
            }
        }
        Instr::Match(matcher) => {
            w.u8(OP_MATCH);
            w.u32(*matcher);
        }
        Instr::MatchAll { start, len } => {
            w.u8(OP_MATCH_ALL);
            w.u32(*start);
            w.u16(*len);
        }
        Instr::MatchAny { start, len } => {
            w.u8(OP_MATCH_ANY);
            w.u32(*start);
            w.u16(*len);
        }
        Instr::Assert(matcher) => {
            w.u8(OP_ASSERT);
            w.u32(*matcher);
        }
        Instr::Extract { name, source } => {
            w.u8(OP_EXTRACT);
            w.u32(*name);
            w.u32(*source);
        }
        Instr::IfMatch { matcher, else_pc } => {
            w.u8(OP_IF_MATCH);
            w.u32(*matcher);
            w.u32(*else_pc);
        }
        Instr::Repeat { count, end_pc } => {
            w.u8(OP_REPEAT);
            w.u32(*count);
            w.u32(*end_pc);
        }
        Instr::LoopBack => w.u8(OP_LOOP_BACK),
        Instr::Break => w.u8(OP_BREAK),
        Instr::Save { from, to } => {
            w.u8(OP_SAVE);
            w.u32(*from);
            w.u32(*to);
        }
        Instr::Evidence(kind) => {
            w.u8(OP_EVIDENCE);
            w.u32(*kind);
        }
        Instr::Retry { probe, count } => {
            w.u8(OP_RETRY);
            w.u32(*probe);
            w.u32(*count);
        }
        Instr::RetryDelay(value) => {
            w.u8(OP_RETRY_DELAY);
            w.u32(*value);
        }
        Instr::Sleep(value) => {
            w.u8(OP_SLEEP);
            w.u32(*value);
        }
        Instr::Stop => w.u8(OP_STOP),
        Instr::Fail => w.u8(OP_FAIL),
        Instr::Continue => w.u8(OP_CONTINUE),
        Instr::Exit => w.u8(OP_EXIT),
    }
}

fn read_instr(r: &mut Reader<'_>) -> Result<Instr, BytecodeError> {
    Ok(match r.u8()? {
        OP_SET => Instr::Set {
            name: r.u32()?,
            value: r.u32()?,
        },
        OP_SEND => {
            let probe = r.u32()?;
            let payload = if r.u8()? == 0 {
                None
            } else {
                Some(r.u32()?)
            };
            Instr::Send { probe, payload }
        }
        OP_MATCH => Instr::Match(r.u32()?),
        OP_MATCH_ALL => Instr::MatchAll {
            start: r.u32()?,
            len: r.u16()?,
        },
        OP_MATCH_ANY => Instr::MatchAny {
            start: r.u32()?,
            len: r.u16()?,
        },
        OP_ASSERT => Instr::Assert(r.u32()?),
        OP_EXTRACT => Instr::Extract {
            name: r.u32()?,
            source: r.u32()?,
        },
        OP_IF_MATCH => Instr::IfMatch {
            matcher: r.u32()?,
            else_pc: r.u32()?,
        },
        OP_REPEAT => Instr::Repeat {
            count: r.u32()?,
            end_pc: r.u32()?,
        },
        OP_LOOP_BACK => Instr::LoopBack,
        OP_BREAK => Instr::Break,
        OP_SAVE => Instr::Save {
            from: r.u32()?,
            to: r.u32()?,
        },
        OP_EVIDENCE => Instr::Evidence(r.u32()?),
        OP_RETRY => Instr::Retry {
            probe: r.u32()?,
            count: r.u32()?,
        },
        OP_RETRY_DELAY => Instr::RetryDelay(r.u32()?),
        OP_SLEEP => Instr::Sleep(r.u32()?),
        OP_STOP => Instr::Stop,
        OP_FAIL => Instr::Fail,
        OP_CONTINUE => Instr::Continue,
        OP_EXIT => Instr::Exit,
        _ => return Err(BytecodeError::Corrupt("opcode")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = vec![0x52, 0x55, 0x53, 0x4f, 0x01, 0xff];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex_to_bytes(&hex).unwrap(), bytes);
    }
}
