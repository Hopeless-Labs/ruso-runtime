use std::collections::HashMap;
use std::time::Duration;

use regex::Regex;
use reqwest::Client;

use crate::contract::{EvidenceKind, ExtractSource};
use crate::runtime::binary;
use crate::runtime::bytecode::{BytecodeProgram, Instr};
use crate::runtime::context::{Context, LoopFrame, LoopState, VariableValue};
use crate::runtime::dns::{resolve_host, run_dns_probe};
use crate::runtime::duration::parse_duration;
use crate::runtime::error::RuntimeError;
use crate::runtime::http::{build_client, execute_http};
use crate::runtime::interpolate::interpolate;
use crate::runtime::matcher::{evaluate, evaluate_all, evaluate_any};
use crate::runtime::port_cache::{PortCache, PortCheck, scan_target_host_port};
use crate::runtime::report::Report;
use crate::runtime::response::ProbeResponse;
use crate::runtime::response::SocketResponse;
use crate::runtime::session::{
    ProbeSession, open_tcp_session, open_udp_session, read_opts_from_spec,
};
use crate::runtime::socket::{
    exchange_tcp, exchange_udp, tcp_session_exchange, udp_session_exchange,
};
use crate::runtime::spec::ProbeKind;
use crate::runtime::spec::SocketProbeSpec;

#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub base_url: String,
    /// Connect timeout for HTTP requests and TCP/UDP/DNS probes.
    pub default_timeout: Duration,
    /// Per-read I/O timeout for socket probes (TCP/UDP/DNS). Falls back to
    /// `default_timeout` if not explicitly tuned.
    pub read_timeout: Duration,
    /// Maximum HTTP response body size in bytes. Larger responses are
    /// truncated at this boundary to bound memory use against malicious
    /// or misconfigured targets.
    pub max_response_bytes: usize,
    pub follow_redirect: bool,
    pub verify_ssl: bool,
    pub proxy: Option<String>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            default_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(10),
            max_response_bytes: 10 * 1024 * 1024, // 10 MiB
            follow_redirect: true,
            verify_ssl: false,
            proxy: None,
        }
    }
}

pub struct Executor {
    config: ExecutorConfig,
    program: BytecodeProgram,
    client: Client,
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    /// True when `finalize_finding()` produced a finding (metadata + matchers passed).
    pub detected: bool,
    /// Check did not run because a required socket port was closed (see `skip_reason`).
    pub skipped: bool,
    pub skip_reason: Option<String>,
    /// Port probes performed before execution (empty for HTTP-only checks).
    pub port_checks: Vec<PortCheck>,
    pub report: Report,
    pub variables: HashMap<String, VariableValue>,
    pub metadata: crate::runtime::spec::CheckMetadata,
}

impl Executor {
    pub fn from_bytes(config: ExecutorConfig, bytes: &[u8]) -> Result<Self, RuntimeError> {
        let program = binary::decode(bytes).map_err(RuntimeError::Bytecode)?;
        Self::from_bytecode(config, program)
    }

    pub fn from_bytecode(
        config: ExecutorConfig,
        program: BytecodeProgram,
    ) -> Result<Self, RuntimeError> {
        let client = build_client(
            Some(config.default_timeout),
            config.follow_redirect,
            config.verify_ssl,
            config.proxy.as_deref(),
        )?;
        Ok(Self {
            config,
            program,
            client,
        })
    }

    pub fn bytecode(&self) -> &BytecodeProgram {
        &self.program
    }

    pub async fn run(&self) -> Result<ExecutionResult, RuntimeError> {
        self.run_bytecode().await
    }

    fn client_for_http(
        &self,
        spec: &crate::runtime::spec::HttpRequestSpec,
    ) -> Result<Client, RuntimeError> {
        let verify_ssl = spec.verify_ssl.unwrap_or(self.config.verify_ssl);
        let follow_redirect = spec.follow_redirect.unwrap_or(self.config.follow_redirect);
        if verify_ssl == self.config.verify_ssl && follow_redirect == self.config.follow_redirect {
            return Ok(self.client.clone());
        }
        build_client(
            Some(self.config.default_timeout),
            follow_redirect,
            verify_ssl,
            self.config.proxy.as_deref(),
        )
    }

    async fn run_bytecode(&self) -> Result<ExecutionResult, RuntimeError> {
        let cache = PortCache::global();
        let (port_checks, closed) = cache
            .check_for_run(&self.program.spec, &self.config.base_url)
            .await;
        if let Some((host, port)) = closed {
            return Ok(ExecutionResult {
                success: true,
                detected: false,
                skipped: true,
                skip_reason: Some(format!("port {host}:{port} closed")),
                port_checks,
                report: Report::default(),
                variables: HashMap::new(),
                metadata: self.program.spec.metadata.clone(),
            });
        }

        let mut context = Context::from_spec(&self.program.spec);
        inject_scan_target_variables(&mut context, &self.config.base_url);
        let mut pc: usize = 0;

        while pc < self.program.code.len() {
            match &self.program.code[pc] {
                Instr::Set { name, value } => {
                    let name = &self.program.strings[*name as usize];
                    let value = &self.program.strings[*value as usize];
                    context.set_variable(name.clone(), interpolate(value, &context.variables)?);
                    pc += 1;
                }
                Instr::SetList { name, start, len } => {
                    let name = &self.program.strings[*name as usize];
                    let values = self.program.strings
                        [*start as usize..(*start + *len as u32) as usize]
                        .iter()
                        .map(|value| interpolate(value, &context.variables))
                        .collect::<Result<Vec<_>, _>>()?;
                    context.set_list_variable(name.clone(), values);
                    pc += 1;
                }
                Instr::Send { probe, payload } => {
                    let name = &self.program.strings[*probe as usize];
                    let payload_override =
                        payload.map(|id| self.program.payloads[id as usize].clone());
                    tracing::trace!(probe = %name, "send");
                    self.send_probe(name, payload_override, &mut context)
                        .await?;
                    pc += 1;
                }
                Instr::Match(matcher) => {
                    self.apply_match(*matcher as usize, &mut context)?;
                    pc += 1;
                }
                Instr::MatchAll { start, len } => {
                    self.apply_match_all(*start as usize, *len as usize, &mut context)?;
                    pc += 1;
                }
                Instr::MatchAny { start, len } => {
                    self.apply_match_any(*start as usize, *len as usize, &mut context)?;
                    pc += 1;
                }
                Instr::Assert(matcher) => {
                    self.require_assert(*matcher as usize, &context)?;
                    pc += 1;
                }
                Instr::Extract { name, source } => {
                    if context.matched {
                        let name = &self.program.strings[*name as usize];
                        let source = &self.program.extracts[*source as usize];
                        self.extract(name, source, &mut context)?;
                    }
                    pc += 1;
                }
                Instr::IfMatch { matcher, else_pc } => {
                    if !context.matched || !self.matches_idx(*matcher as usize, &context)? {
                        pc = *else_pc as usize;
                    } else {
                        pc += 1;
                    }
                }
                Instr::Repeat { count, end_pc } => {
                    if *count == 0 {
                        pc = *end_pc as usize;
                        continue;
                    }
                    context.loop_stack.push(LoopFrame {
                        state: LoopState::Repeat { remaining: *count },
                        head_pc: pc + 1,
                        continue_pc: (*end_pc as usize).saturating_sub(1),
                        end_pc: *end_pc as usize,
                    });
                    pc += 1;
                }
                Instr::ForList {
                    item,
                    start,
                    len,
                    end_pc,
                } => {
                    let item = self.program.strings[*item as usize].clone();
                    let values = self.program.strings
                        [*start as usize..(*start + *len as u32) as usize]
                        .iter()
                        .map(|value| interpolate(value, &context.variables))
                        .collect::<Result<Vec<_>, _>>()?;
                    if values.is_empty() {
                        pc = *end_pc as usize;
                        continue;
                    }
                    let previous = context.variables.get(&item).cloned();
                    context.set_variable(item.clone(), values[0].clone());
                    context.loop_stack.push(LoopFrame {
                        state: LoopState::ForEach {
                            item,
                            values,
                            index: 0,
                            previous,
                        },
                        head_pc: pc + 1,
                        continue_pc: (*end_pc as usize).saturating_sub(1),
                        end_pc: *end_pc as usize,
                    });
                    pc += 1;
                }
                Instr::ForVar { item, list, end_pc } => {
                    let item = self.program.strings[*item as usize].clone();
                    let list_name = &self.program.strings[*list as usize];
                    let values = match context.variables.get(list_name) {
                        Some(VariableValue::List(values)) => values.clone(),
                        Some(VariableValue::String(_)) => {
                            return Err(RuntimeError::Other(format!(
                                "variable {list_name} is not a list"
                            )));
                        }
                        None => Vec::new(),
                    };
                    if values.is_empty() {
                        pc = *end_pc as usize;
                        continue;
                    }
                    let previous = context.variables.get(&item).cloned();
                    context.set_variable(item.clone(), values[0].clone());
                    context.loop_stack.push(LoopFrame {
                        state: LoopState::ForEach {
                            item,
                            values,
                            index: 0,
                            previous,
                        },
                        head_pc: pc + 1,
                        continue_pc: (*end_pc as usize).saturating_sub(1),
                        end_pc: *end_pc as usize,
                    });
                    pc += 1;
                }
                Instr::LoopBack => {
                    enum LoopAction {
                        Jump(usize),
                        End(usize),
                        SetAndJump {
                            item: String,
                            value: String,
                            head_pc: usize,
                        },
                        RestoreAndEnd {
                            item: String,
                            previous: Option<VariableValue>,
                            end_pc: usize,
                        },
                    }

                    let action = {
                        let frame = context
                            .loop_stack
                            .last_mut()
                            .ok_or_else(|| RuntimeError::Other("loop_back outside loop".into()))?;
                        match &mut frame.state {
                            LoopState::Repeat { remaining } => {
                                if *remaining > 1 {
                                    *remaining -= 1;
                                    LoopAction::Jump(frame.head_pc)
                                } else {
                                    LoopAction::End(frame.end_pc)
                                }
                            }
                            LoopState::ForEach {
                                item,
                                values,
                                index,
                                previous,
                            } => {
                                if *index + 1 < values.len() {
                                    *index += 1;
                                    LoopAction::SetAndJump {
                                        item: item.clone(),
                                        value: values[*index].clone(),
                                        head_pc: frame.head_pc,
                                    }
                                } else {
                                    LoopAction::RestoreAndEnd {
                                        item: item.clone(),
                                        previous: previous.clone(),
                                        end_pc: frame.end_pc,
                                    }
                                }
                            }
                        }
                    };

                    match action {
                        LoopAction::Jump(head_pc) => {
                            pc = head_pc;
                        }
                        LoopAction::End(end_pc) => {
                            context.loop_stack.pop();
                            pc = end_pc;
                        }
                        LoopAction::SetAndJump {
                            item,
                            value,
                            head_pc,
                        } => {
                            context.set_variable(item, value);
                            pc = head_pc;
                        }
                        LoopAction::RestoreAndEnd {
                            item,
                            previous,
                            end_pc,
                        } => {
                            context.loop_stack.pop();
                            context.restore_or_remove_variable(item, previous);
                            pc = end_pc;
                        }
                    }
                }
                Instr::Break => {
                    let frame = context
                        .loop_stack
                        .pop()
                        .ok_or_else(|| RuntimeError::Other("break outside loop".into()))?;
                    if let LoopState::ForEach { item, previous, .. } = frame.state {
                        context.restore_or_remove_variable(item, previous);
                    }
                    pc = frame.end_pc;
                }
                Instr::Save { from, to } => {
                    let from = &self.program.strings[*from as usize];
                    let to = &self.program.strings[*to as usize];
                    context.alias_response(from, to);
                    pc += 1;
                }
                Instr::Evidence(kind) => {
                    if !context.matched {
                        pc += 1;
                        continue;
                    }
                    let kind = &self.program.evidence[*kind as usize];
                    let text = self.collect_evidence(kind, &context)?;
                    context.evidence.push(text);
                    pc += 1;
                }
                Instr::Retry { probe, count } => {
                    let name = &self.program.strings[*probe as usize];
                    self.retry_send(name, *count, &mut context).await?;
                    pc += 1;
                }
                Instr::RetryDelay(value) => {
                    let value = &self.program.strings[*value as usize];
                    context.retry_delay = Some(parse_duration(value)?);
                    pc += 1;
                }
                Instr::Sleep(value) => {
                    let value = &self.program.strings[*value as usize];
                    tokio::time::sleep(parse_duration(value)?).await;
                    pc += 1;
                }
                Instr::Stop => {
                    tracing::warn!("stop");
                    context.emit_finding = false;
                    break;
                }
                Instr::Exit => {
                    tracing::info!("exit");
                    break;
                }
                Instr::Fail => {
                    tracing::error!("fail");
                    context.failed = true;
                    return Err(RuntimeError::Flow("fail".into()));
                }
                Instr::Continue => {
                    let continue_pc = context
                        .loop_stack
                        .last()
                        .ok_or_else(|| RuntimeError::Other("continue outside loop".into()))?
                        .continue_pc;
                    pc = continue_pc;
                }
            }
        }

        context.close_sessions();
        context.finalize_finding();

        Ok(ExecutionResult {
            success: !context.failed,
            detected: !context.report.findings.is_empty(),
            skipped: false,
            skip_reason: None,
            port_checks,
            report: context.report,
            variables: context.variables,
            metadata: context.metadata,
        })
    }

    fn interpolate_socket_spec(
        &self,
        spec: &SocketProbeSpec,
        context: &Context,
    ) -> Result<SocketProbeSpec, RuntimeError> {
        let payload = spec
            .payload
            .as_ref()
            .map(|bytes| {
                if let Ok(text) = std::str::from_utf8(bytes) {
                    interpolate(text, &context.variables).map(|value| value.into_bytes())
                } else {
                    Ok(bytes.clone())
                }
            })
            .transpose()?;

        Ok(SocketProbeSpec {
            host: interpolate(&spec.host, &context.variables)?,
            port: spec.port,
            payload,
            tls: spec.tls,
            session: spec.session,
            read_max: spec.read_max,
            read_idle_ms: spec.read_idle_ms,
        })
    }

    #[tracing::instrument(level = "trace", skip(self, context), fields(probe = name))]
    async fn send_probe(
        &self,
        name: &str,
        payload_override: Option<Vec<u8>>,
        context: &mut Context,
    ) -> Result<(), RuntimeError> {
        let probe = self
            .program
            .spec
            .probes
            .get(name)
            .ok_or_else(|| RuntimeError::UnknownTarget(name.to_string()))?
            .clone();

        let timeout = context.retry_delay.unwrap_or(self.config.default_timeout);

        let response = match probe {
            ProbeKind::Http(spec) => {
                let client = self.client_for_http(&spec)?;
                let http = execute_http(
                    &client,
                    &self.config.base_url,
                    &spec,
                    &context.variables,
                    self.config.max_response_bytes,
                )
                .await?;
                ProbeResponse::Http(http)
            }
            ProbeKind::Dns(spec) => {
                let mut spec = self.interpolate_socket_spec(&spec, context)?;
                if let Some(p) = payload_override {
                    spec.payload = Some(p);
                }
                if spec.is_dns_resolver_mode() {
                    ProbeResponse::DnsResolve(resolve_host(&spec.host).await?)
                } else {
                    ProbeResponse::Socket(
                        run_dns_probe(&spec, timeout, self.config.read_timeout).await?,
                    )
                }
            }
            ProbeKind::Tcp(spec) => {
                let spec = self.interpolate_socket_spec(&spec, context)?;
                let port = spec
                    .port
                    .ok_or_else(|| RuntimeError::Other("tcp probe requires port".to_string()))?;
                let payload = payload_override.or(spec.payload.clone());
                ProbeResponse::Socket(
                    self.exchange_tcp_probe(
                        name,
                        &spec,
                        port,
                        payload.as_deref(),
                        timeout,
                        context,
                    )
                    .await?,
                )
            }
            ProbeKind::Udp(spec) => {
                let spec = self.interpolate_socket_spec(&spec, context)?;
                let port = spec
                    .port
                    .ok_or_else(|| RuntimeError::Other("udp probe requires port".to_string()))?;
                let payload = payload_override.or(spec.payload.clone());
                ProbeResponse::Socket(
                    self.exchange_udp_probe(
                        name,
                        &spec,
                        port,
                        payload.as_deref(),
                        timeout,
                        context,
                    )
                    .await?,
                )
            }
        };

        log_probe_response(name, &response);

        let append_session = probe_session_enabled(name, &self.program.spec);
        if append_session
            && let (ProbeResponse::Socket(chunk), Some(ProbeResponse::Socket(existing))) =
                (&response, context.responses.get(name))
        {
            let mut merged = existing.clone();
            merged.data.extend_from_slice(&chunk.data);
            context.store_response(name, ProbeResponse::Socket(merged));
            return Ok(());
        }
        context.store_response(name, response);
        Ok(())
    }

    async fn exchange_tcp_probe(
        &self,
        name: &str,
        spec: &SocketProbeSpec,
        port: u16,
        payload: Option<&[u8]>,
        timeout: Duration,
        context: &mut Context,
    ) -> Result<SocketResponse, RuntimeError> {
        let read = read_opts_from_spec(spec);
        let io_timeout = self.config.read_timeout;

        if spec.session {
            if let Some(ProbeSession::Tcp(session)) = context.sessions.get_mut(name) {
                let data = tcp_session_exchange(session, payload, &read, io_timeout).await?;
                return Ok(SocketResponse {
                    host: spec.host.clone(),
                    port,
                    data,
                });
            }
            let mut session =
                open_tcp_session(&spec.host, port, spec.tls, self.config.verify_ssl, timeout)
                    .await?;
            let data = tcp_session_exchange(&mut session, payload, &read, io_timeout).await?;
            context
                .sessions
                .insert(name.to_string(), ProbeSession::Tcp(session));
            return Ok(SocketResponse {
                host: spec.host.clone(),
                port,
                data,
            });
        }

        let mut send_spec = spec.clone();
        send_spec.payload = payload.map(|p| p.to_vec());
        exchange_tcp(
            &send_spec.host,
            port,
            &send_spec,
            self.config.verify_ssl,
            timeout,
            io_timeout,
        )
        .await
    }

    async fn exchange_udp_probe(
        &self,
        name: &str,
        spec: &SocketProbeSpec,
        port: u16,
        payload: Option<&[u8]>,
        timeout: Duration,
        context: &mut Context,
    ) -> Result<SocketResponse, RuntimeError> {
        let read = read_opts_from_spec(spec);
        let io_timeout = self.config.read_timeout;

        if spec.tls {
            return Err(RuntimeError::Other("tls is not supported for udp".into()));
        }

        if spec.session {
            if let Some(ProbeSession::Udp(socket)) = context.sessions.get(name) {
                let data = udp_session_exchange(socket, payload, &read, io_timeout).await?;
                return Ok(SocketResponse {
                    host: spec.host.clone(),
                    port,
                    data,
                });
            }
            let socket = open_udp_session(&spec.host, port, timeout).await?;
            let data = udp_session_exchange(&socket, payload, &read, io_timeout).await?;
            context
                .sessions
                .insert(name.to_string(), ProbeSession::Udp(socket));
            return Ok(SocketResponse {
                host: spec.host.clone(),
                port,
                data,
            });
        }

        exchange_udp(&spec.host, port, payload, spec, timeout, io_timeout).await
    }

    async fn retry_send(
        &self,
        name: &str,
        count: u32,
        context: &mut Context,
    ) -> Result<(), RuntimeError> {
        let delay = context.retry_delay.unwrap_or(Duration::from_secs(1));
        let mut last_error = None;

        for attempt in 0..count {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
            }
            match self.send_probe(name, None, context).await {
                Ok(()) => return Ok(()),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error
            .unwrap_or_else(|| RuntimeError::Other(format!("retry send failed for {name}"))))
    }

    fn apply_match(&self, matcher_idx: usize, context: &mut Context) -> Result<(), RuntimeError> {
        if !context.matched {
            return Ok(());
        }
        let matcher = &self.program.matchers[matcher_idx];
        if !self.matches_idx(matcher_idx, context)? {
            tracing::trace!(target = %matcher.field.target, ?matcher.predicate, "match failed");
            context.matched = false;
        } else {
            tracing::trace!(target = %matcher.field.target, ?matcher.predicate, "match ok");
        }
        Ok(())
    }

    fn apply_match_all(
        &self,
        start: usize,
        len: usize,
        context: &mut Context,
    ) -> Result<(), RuntimeError> {
        if !context.matched {
            return Ok(());
        }
        let matchers = &self.program.matchers[start..start + len];
        if !evaluate_all(matchers, &context.responses)? {
            tracing::trace!(count = len, "match all failed");
            context.matched = false;
        } else {
            tracing::trace!(count = len, "match all ok");
        }
        Ok(())
    }

    fn apply_match_any(
        &self,
        start: usize,
        len: usize,
        context: &mut Context,
    ) -> Result<(), RuntimeError> {
        if !context.matched {
            return Ok(());
        }
        let matchers = &self.program.matchers[start..start + len];
        if !evaluate_any(matchers, &context.responses)? {
            tracing::trace!(count = len, "match any failed");
            context.matched = false;
        } else {
            tracing::trace!(count = len, "match any ok");
        }
        Ok(())
    }

    fn require_assert(&self, matcher_idx: usize, context: &Context) -> Result<(), RuntimeError> {
        if !context.matched {
            return Ok(());
        }
        if self.matches_idx(matcher_idx, context)? {
            return Ok(());
        }
        let matcher = &self.program.matchers[matcher_idx];
        let detail = format!("target {}", matcher.field.target);
        Err(RuntimeError::assert_failed(matcher, detail))
    }

    fn matches_idx(&self, matcher_idx: usize, context: &Context) -> Result<bool, RuntimeError> {
        let matcher = &self.program.matchers[matcher_idx];
        let response = context
            .response(&matcher.field.target)
            .ok_or_else(|| RuntimeError::UnknownTarget(matcher.field.target.clone()))?;
        evaluate(matcher, response)
    }

    fn extract(
        &self,
        name: &str,
        source: &ExtractSource,
        context: &mut Context,
    ) -> Result<(), RuntimeError> {
        let value = match source {
            ExtractSource::Body { target, regex } => {
                let response = context
                    .response(target)
                    .ok_or_else(|| RuntimeError::UnknownTarget(target.clone()))?;
                let http = response
                    .as_http()
                    .map_err(|_| RuntimeError::WrongProbeKind {
                        name: target.clone(),
                    })?;
                match regex {
                    Some(pattern) => extract_regex(&http.body, pattern)?,
                    None => http.body.clone(),
                }
            }
            ExtractSource::Header {
                target,
                name: header,
            } => {
                let response = context
                    .response(target)
                    .ok_or_else(|| RuntimeError::UnknownTarget(target.clone()))?;
                let http = response
                    .as_http()
                    .map_err(|_| RuntimeError::WrongProbeKind {
                        name: target.clone(),
                    })?;
                http.headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(header))
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default()
            }
        };

        if value.is_empty() {
            return Err(RuntimeError::ExtractFailed {
                name: name.to_string(),
                reason: "empty result".into(),
            });
        }

        tracing::trace!(variable = %name, "extracted");
        context.set_variable(name, value);
        Ok(())
    }

    fn collect_evidence(
        &self,
        kind: &EvidenceKind,
        context: &Context,
    ) -> Result<String, RuntimeError> {
        match kind {
            EvidenceKind::BodyRef(target) => {
                let response = context
                    .response(target)
                    .ok_or_else(|| RuntimeError::UnknownTarget(target.clone()))?;
                let http = response.as_http().map_err(|_| RuntimeError::Other(format!(
                    "evidence {target}.body requires an http probe; use evidence {target}.response or evidence {target} regex for socket/dns"
                )))?;
                Ok(crate::util::truncate_str(&http.body, 500))
            }
            EvidenceKind::ResponseRef(target) => {
                let response = context
                    .response(target)
                    .ok_or_else(|| RuntimeError::UnknownTarget(target.clone()))?;
                Ok(crate::util::truncate_str(&evidence_haystack(response), 500))
            }
            EvidenceKind::Regex { target, pattern } => {
                let response = context
                    .response(target)
                    .ok_or_else(|| RuntimeError::UnknownTarget(target.clone()))?;
                let haystack = evidence_haystack(response);
                extract_regex(&haystack, pattern).map_err(|_| {
                    RuntimeError::Other(format!(
                        "evidence regex on {target} did not match: {pattern}"
                    ))
                })
            }
        }
    }
}

fn inject_scan_target_variables(context: &mut Context, base_url: &str) {
    if let Some((host, port)) = scan_target_host_port(base_url) {
        context.set_variable("scan_host", host);
        context.set_variable("scan_port", port.to_string());
    }
    if !base_url.is_empty() {
        context.set_variable("scan_url", base_url.to_string());
    }
}

fn evidence_haystack(response: &ProbeResponse) -> String {
    match response {
        ProbeResponse::Http(http) => http.body.clone(),
        ProbeResponse::DnsResolve(dns) => dns.answers.join(" "),
        // Socket data is bytes; evidence is human-facing, so a lossy decode is
        // intentional here. Matching elsewhere still operates on raw bytes.
        ProbeResponse::Socket(sock) => sock.data_lossy().into_owned(),
    }
}

fn probe_session_enabled(name: &str, spec: &crate::runtime::spec::ProgramSpec) -> bool {
    spec.probes.get(name).is_some_and(|kind| match kind {
        ProbeKind::Tcp(s) | ProbeKind::Udp(s) | ProbeKind::Dns(s) => s.session,
        ProbeKind::Http(_) => false,
    })
}

fn extract_regex(body: &str, pattern: &str) -> Result<String, RuntimeError> {
    let regex = Regex::new(pattern)?;
    let captures = regex
        .captures(body)
        .ok_or_else(|| RuntimeError::ExtractFailed {
            name: "regex".into(),
            reason: format!("pattern not found: {pattern}"),
        })?;
    let matched = captures
        .get(1)
        .or_else(|| captures.get(0))
        .map(|value| value.as_str().to_string())
        .unwrap_or_default();
    if matched.is_empty() {
        return Err(RuntimeError::ExtractFailed {
            name: "regex".into(),
            reason: format!("empty capture for: {pattern}"),
        });
    }
    Ok(matched)
}

fn log_probe_response(name: &str, response: &ProbeResponse) {
    match response {
        ProbeResponse::Http(http) => {
            tracing::trace!(
                probe = name,
                status = http.status,
                elapsed_ms = http.elapsed.as_millis() as u64,
                body_bytes = http.body.len(),
                "http response"
            );
        }
        ProbeResponse::DnsResolve(dns) => {
            tracing::trace!(
                probe = name,
                host = %dns.host,
                answers = dns.answers.len(),
                "dns resolve"
            );
        }
        ProbeResponse::Socket(sock) => {
            tracing::trace!(
                probe = name,
                host = %sock.host,
                port = sock.port,
                data_bytes = sock.data.len(),
                "socket response"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        CmpOp, CmpValue, FieldKind, MatchPredicate, QualifiedField, QualifiedMatch, Severity,
    };
    use crate::runtime::bytecode::BytecodeProgram;
    use crate::runtime::spec::{CheckMetadata, ProgramSpec};

    fn metadata_only_bytecode() -> BytecodeProgram {
        BytecodeProgram {
            spec: ProgramSpec {
                probes: Default::default(),
                metadata: CheckMetadata {
                    name: Some("Metadata only".into()),
                    severity: Some(Severity::Low),
                    ..CheckMetadata::default()
                },
            },
            code: vec![],
            strings: vec![],
            payloads: vec![],
            matchers: vec![],
            extracts: vec![],
            evidence: vec![],
        }
    }

    #[tokio::test]
    async fn run_fail_opcode_returns_error() {
        let bytecode = BytecodeProgram {
            spec: ProgramSpec {
                probes: Default::default(),
                metadata: CheckMetadata::default(),
            },
            code: vec![Instr::Fail],
            strings: vec![],
            payloads: vec![],
            matchers: vec![],
            extracts: vec![],
            evidence: vec![],
        };
        let config = ExecutorConfig {
            base_url: "http://127.0.0.1".into(),
            ..ExecutorConfig::default()
        };
        let executor = Executor::from_bytecode(config, bytecode).unwrap();
        assert!(executor.run().await.is_err());
    }

    #[tokio::test]
    async fn match_without_send_returns_unknown_target() {
        let bytecode = BytecodeProgram {
            spec: ProgramSpec {
                probes: Default::default(),
                metadata: CheckMetadata::default(),
            },
            code: vec![Instr::Match(0)],
            strings: vec![],
            payloads: vec![],
            matchers: vec![QualifiedMatch {
                field: QualifiedField {
                    target: "home".into(),
                    kind: FieldKind::Status,
                },
                predicate: MatchPredicate::Compare {
                    op: CmpOp::Eq,
                    value: CmpValue::Number(200),
                },
            }],
            extracts: vec![],
            evidence: vec![],
        };
        let config = ExecutorConfig {
            base_url: "http://127.0.0.1".into(),
            ..ExecutorConfig::default()
        };
        let executor = Executor::from_bytecode(config, bytecode).unwrap();
        let err = executor.run().await.expect_err("match without prior send");
        assert!(matches!(err, RuntimeError::UnknownTarget(_)));
    }

    #[tokio::test]
    async fn metadata_only_can_emit_finding_without_network() {
        let config = ExecutorConfig {
            base_url: "http://127.0.0.1".into(),
            ..ExecutorConfig::default()
        };
        let executor = Executor::from_bytecode(config, metadata_only_bytecode()).unwrap();
        assert!(executor.bytecode().code.is_empty());
        let result = executor.run().await.expect("metadata run");
        assert!(result.detected);
        assert_eq!(result.report.findings[0].name, "Metadata only");
    }
}
