use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::path::{Component, Path, PathBuf};

const DANGEROUS_TERMS: &[&str] = &[
    "delete",
    "remove",
    "destroy",
    "drop",
    "wipe",
    "reset",
    "pay",
    "purchase",
    "buy",
    "checkout",
    "subscribe",
    "unsubscribe",
    "transfer",
    "wire",
    "send money",
    "refund",
    "submit",
    "publish",
    "deploy",
    "merge",
    "approve",
    "grant",
    "chmod",
    "chown",
    "sudo",
    "rm -rf",
];
const SECRET_TERMS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "api-key",
    "private_key",
    "private-key",
    "credential",
    "authorization",
    "cookie",
    "session",
];
const PII_TERMS: &[&str] = &[
    "email",
    "phone",
    "address",
    "ssn",
    "social security",
    "credit card",
    "card number",
    "cvv",
    "birth",
    "dob",
];

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    MissingExecutable,
    InvalidJson(String),
    InvalidUrl(String),
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NormalizeError::MissingExecutable => {
                write!(f, "request must contain either action or tool")
            }
            NormalizeError::InvalidJson(msg) => write!(f, "invalid json: {msg}"),
            NormalizeError::InvalidUrl(url) => write!(f, "invalid url: {url}"),
        }
    }
}

impl std::error::Error for NormalizeError {}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawRequest {
    pub request_id: Option<String>,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub timestamp: Option<String>,
    pub source: Option<String>,
    pub task: Option<String>,
    pub observation: Option<RawObservation>,
    pub action: Option<RawAction>,
    pub tool: Option<RawToolCall>,
    pub policy_hints: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawObservation {
    pub url: Option<String>,
    pub title: Option<String>,
    pub viewport: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawAction {
    pub op: String,
    pub target: Option<RawTarget>,
    pub value: Option<String>,
    pub key: Option<String>,
    pub scroll_delta: Option<(i64, i64)>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawTarget {
    pub css_selector: Option<String>,
    pub xpath: Option<String>,
    pub tag: Option<String>,
    pub role: Option<String>,
    pub text: Option<String>,
    pub aria_label: Option<String>,
    pub name: Option<String>,
    pub id: Option<String>,
    pub bbox: Option<Vec<f64>>,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawToolCall {
    pub name: String,
    pub args: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalAction {
    Navigate,
    Read,
    Write,
    Execute,
    Network,
    UiClick,
    UiType,
    UiSelect,
    UiScroll,
    UiHover,
    KeyPress,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    Public,
    Internal,
    Sensitive,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionHint {
    Allow,
    Review,
    Deny,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedRequest {
    pub request_id: Option<String>,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub timestamp: Option<String>,
    pub canonical_action: CanonicalAction,
    pub capability: String,
    pub resource: Resource,
    pub scope: BTreeMap<String, String>,
    pub sensitivity: Sensitivity,
    pub risk_level: RiskLevel,
    pub risk_score: u8,
    pub decision_hint: DecisionHint,
    pub requires_confirmation: bool,
    pub redactions: Vec<Redaction>,
    pub reasons: Vec<String>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    pub kind: String,
    pub identifier: String,
    pub url: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub selector: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redaction {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Provenance {
    pub source: Option<String>,
    pub raw_op: Option<String>,
    pub tool_name: Option<String>,
}

pub fn raw_request_from_json(input: &str) -> Result<RawRequest, NormalizeError> {
    let value = parse_json(input)?;
    RawRequest::from_json(&value)
}

pub fn normalize_json(input: &str) -> Result<String, NormalizeError> {
    let raw = raw_request_from_json(input)?;
    Ok(normalize(raw)?.to_json_pretty())
}

pub fn normalize(raw: RawRequest) -> Result<NormalizedRequest, NormalizeError> {
    if raw.action.is_none() && raw.tool.is_none() {
        return Err(NormalizeError::MissingExecutable);
    }

    let mut reasons = Vec::new();
    let mut redactions = Vec::new();
    let (canonical_action, resource, raw_op, tool_name, mut sensitivity, mut score) =
        if let Some(action) = raw.action.as_ref() {
            normalize_action(
                action,
                raw.observation.as_ref(),
                &mut reasons,
                &mut redactions,
            )?
        } else {
            normalize_tool(raw.tool.as_ref().unwrap(), &mut reasons, &mut redactions)?
        };

    if contains_any(raw.task.as_deref().unwrap_or_default(), DANGEROUS_TERMS) {
        score = score.saturating_add(15);
        reasons.push("task text contains a dangerous or irreversible intent".to_string());
    }
    if let Some(JsonValue::String(classification)) = raw.policy_hints.get("sensitivity") {
        let hinted = parse_sensitivity(classification);
        if hinted > sensitivity {
            reasons.push(format!(
                "policy hint raised sensitivity to {classification}"
            ));
            sensitivity = hinted;
        }
    }
    if let Some(JsonValue::Number(delta)) = raw.policy_hints.get("risk_score_delta") {
        let d = (*delta).max(0.0).min(100.0) as u8;
        score = score.saturating_add(d);
        reasons.push(format!("policy hint added risk_score_delta={d}"));
    }

    score = score.min(100);
    let risk_level = risk_level(score);
    let decision_hint = match risk_level {
        RiskLevel::Low => DecisionHint::Allow,
        RiskLevel::Medium | RiskLevel::High => DecisionHint::Review,
        RiskLevel::Critical => DecisionHint::Deny,
    };
    let requires_confirmation = !matches!(risk_level, RiskLevel::Low);
    let capability = capability_for(&canonical_action, &resource, &sensitivity);
    let scope = build_scope(&resource, &canonical_action, &sensitivity);

    Ok(NormalizedRequest {
        request_id: raw.request_id,
        agent_id: raw.agent_id,
        user_id: raw.user_id,
        session_id: raw.session_id,
        timestamp: raw.timestamp,
        canonical_action,
        capability,
        resource,
        scope,
        sensitivity,
        risk_level,
        risk_score: score,
        decision_hint,
        requires_confirmation,
        redactions,
        reasons,
        provenance: Provenance {
            source: raw.source,
            raw_op,
            tool_name,
        },
    })
}

fn normalize_action(
    action: &RawAction,
    observation: Option<&RawObservation>,
    reasons: &mut Vec<String>,
    redactions: &mut Vec<Redaction>,
) -> Result<
    (
        CanonicalAction,
        Resource,
        Option<String>,
        Option<String>,
        Sensitivity,
        u8,
    ),
    NormalizeError,
> {
    let op = action.op.trim().to_ascii_uppercase();
    let canonical = match op.as_str() {
        "NAVIGATE" => CanonicalAction::Navigate,
        "CLICK" => CanonicalAction::UiClick,
        "TYPE" => CanonicalAction::UiType,
        "SELECT" => CanonicalAction::UiSelect,
        "SCROLL" => CanonicalAction::UiScroll,
        "HOVER" => CanonicalAction::UiHover,
        "PRESS_KEY" | "KEY" => CanonicalAction::KeyPress,
        _ => CanonicalAction::Unknown,
    };
    let mut sensitivity = Sensitivity::Public;
    let mut score: u8 = match canonical {
        CanonicalAction::Navigate
        | CanonicalAction::Read
        | CanonicalAction::UiScroll
        | CanonicalAction::UiHover => 10,
        CanonicalAction::UiClick | CanonicalAction::UiSelect | CanonicalAction::KeyPress => 25,
        CanonicalAction::UiType | CanonicalAction::Write => 35,
        CanonicalAction::Execute | CanonicalAction::Network => 60,
        CanonicalAction::Unknown => 45,
    };
    let resource = if canonical == CanonicalAction::Navigate {
        normalize_url_resource(action.value.as_deref().unwrap_or_default())?
    } else if let Some(target) = action.target.as_ref() {
        let current_url = observation
            .and_then(|o| o.url.as_deref())
            .and_then(|u| normalize_url(u).ok());
        let domain = current_url.as_deref().and_then(extract_domain);
        Resource {
            kind: "dom_element".to_string(),
            identifier: nonempty(target_identifier(target), "unknown_element"),
            url: current_url,
            domain,
            path: None,
            selector: selector(target),
        }
    } else {
        Resource {
            kind: "browser".to_string(),
            identifier: op.to_ascii_lowercase(),
            url: observation
                .and_then(|o| o.url.as_deref())
                .and_then(|u| normalize_url(u).ok()),
            domain: None,
            path: None,
            selector: None,
        }
    };

    let target_text = action
        .target
        .as_ref()
        .map(target_risk_text)
        .unwrap_or_default();
    if contains_any(&target_text, DANGEROUS_TERMS) {
        score = score.saturating_add(35);
        reasons.push("target text or label indicates a dangerous operation".to_string());
    }
    if contains_any(&target_text, SECRET_TERMS) {
        sensitivity = Sensitivity::Secret;
        score = score.saturating_add(35);
        reasons.push("target metadata indicates a secret input or credential".to_string());
    } else if contains_any(&target_text, PII_TERMS) {
        sensitivity = Sensitivity::Sensitive;
        score = score.saturating_add(20);
        reasons.push("target metadata indicates PII or sensitive user data".to_string());
    }
    if let Some(value) = action.value.as_deref() {
        if looks_secret(value)
            || (canonical == CanonicalAction::UiType && sensitivity == Sensitivity::Secret)
        {
            redactions.push(Redaction {
                field: "action.value".to_string(),
                reason: "secret or credential-like value was withheld from normalized output"
                    .to_string(),
            });
            sensitivity = Sensitivity::Secret;
            score = score.saturating_add(30);
            reasons.push("action value matched secret-value heuristics".to_string());
        }
    }
    Ok((
        canonical,
        resource,
        Some(action.op.clone()),
        None,
        sensitivity,
        score,
    ))
}

fn normalize_tool(
    tool: &RawToolCall,
    reasons: &mut Vec<String>,
    redactions: &mut Vec<Redaction>,
) -> Result<
    (
        CanonicalAction,
        Resource,
        Option<String>,
        Option<String>,
        Sensitivity,
        u8,
    ),
    NormalizeError,
> {
    let name = tool.name.to_ascii_lowercase();
    let mut sensitivity = Sensitivity::Internal;
    let mut score = 35u8;
    let canonical = if contains_any(&name, &["shell", "exec", "command"]) {
        score = 90;
        reasons.push("tool can execute local commands".to_string());
        CanonicalAction::Execute
    } else if contains_any(&name, &["write", "patch", "edit", "delete"]) {
        score = 65;
        CanonicalAction::Write
    } else if contains_any(&name, &["http", "fetch", "request"]) {
        score = 50;
        CanonicalAction::Network
    } else if contains_any(&name, &["read", "open", "list"]) {
        score = 25;
        CanonicalAction::Read
    } else {
        CanonicalAction::Unknown
    };
    let mut resource = Resource {
        kind: "tool".to_string(),
        identifier: tool.name.clone(),
        url: None,
        domain: None,
        path: None,
        selector: None,
    };
    if let Some(path) = string_arg(&tool.args, &["path", "file", "filename"]) {
        let normalized = normalize_path(path);
        resource.kind = "file".to_string();
        resource.identifier = normalized.clone();
        resource.path = Some(normalized);
    }
    if let Some(url) = string_arg(&tool.args, &["url", "uri", "endpoint"]) {
        if let Ok(url_resource) = normalize_url_resource(url) {
            resource = url_resource;
        }
    }
    for (key, value) in &tool.args {
        let text = format!("{key} {}", value.to_compact_json());
        if contains_any(&text, SECRET_TERMS) || looks_secret(&text) {
            sensitivity = Sensitivity::Secret;
            score = score.saturating_add(25);
            redactions.push(Redaction {
                field: format!("tool.args.{key}"),
                reason: "secret-like tool argument was withheld from normalized output".to_string(),
            });
        }
    }
    if contains_any(&name, DANGEROUS_TERMS) {
        score = score.saturating_add(25);
        reasons.push("tool name indicates dangerous or irreversible operation".to_string());
    }
    Ok((
        canonical,
        resource,
        None,
        Some(tool.name.clone()),
        sensitivity,
        score,
    ))
}

fn normalize_url_resource(value: &str) -> Result<Resource, NormalizeError> {
    let url = normalize_url(value)?;
    let domain = extract_domain(&url);
    let path = extract_path(&url);
    Ok(Resource {
        kind: "url".to_string(),
        identifier: url.clone(),
        url: Some(url),
        domain,
        path,
        selector: None,
    })
}

fn normalize_url(value: &str) -> Result<String, NormalizeError> {
    let (scheme, rest) = value
        .split_once("://")
        .ok_or_else(|| NormalizeError::InvalidUrl(value.to_string()))?;
    if scheme.is_empty() || rest.is_empty() || rest.starts_with('/') {
        return Err(NormalizeError::InvalidUrl(value.to_string()));
    }
    let scheme = scheme.to_ascii_lowercase();
    let without_fragment = rest.split('#').next().unwrap_or(rest);
    let (host_port, suffix) = match without_fragment.find('/') {
        Some(idx) => (&without_fragment[..idx], &without_fragment[idx..]),
        None => (without_fragment, "/"),
    };
    let mut host_port = host_port.to_ascii_lowercase();
    if (scheme == "https" && host_port.ends_with(":443"))
        || (scheme == "http" && host_port.ends_with(":80"))
    {
        host_port = host_port
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or(host_port);
    }
    if host_port.is_empty() {
        return Err(NormalizeError::InvalidUrl(value.to_string()));
    }
    Ok(format!("{scheme}://{host_port}{suffix}"))
}

fn extract_domain(url: &str) -> Option<String> {
    url.split_once("://")?
        .1
        .split('/')
        .next()
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
}

fn extract_path(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let idx = rest.find('/').unwrap_or(rest.len());
    Some(if idx < rest.len() {
        rest[idx..].to_string()
    } else {
        "/".to_string()
    })
}

fn normalize_path(path: &str) -> String {
    let p = Path::new(path);
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            Component::RootDir => out.push(component.as_os_str()),
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
        }
    }
    out.to_string_lossy().to_string()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let h = haystack.to_ascii_lowercase();
    needles.iter().any(|needle| h.contains(needle))
}

fn looks_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("-----begin ")
        || value.starts_with("sk-") && value.len() > 18
        || value.starts_with("ghp_") && value.len() > 20
        || value.starts_with("gho_") && value.len() > 20
        || value.starts_with("xoxb-") && value.len() > 20
}

fn nonempty(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn selector(target: &RawTarget) -> Option<String> {
    target
        .css_selector
        .clone()
        .or_else(|| target.xpath.as_ref().map(|x| format!("xpath={x}")))
}

fn target_identifier(target: &RawTarget) -> String {
    target
        .id
        .clone()
        .or_else(|| target.name.clone())
        .or_else(|| target.aria_label.clone())
        .or_else(|| target.text.clone())
        .or_else(|| selector(target))
        .unwrap_or_default()
}

fn target_risk_text(target: &RawTarget) -> String {
    let mut chunks = vec![
        target.text.clone().unwrap_or_default(),
        target.aria_label.clone().unwrap_or_default(),
        target.name.clone().unwrap_or_default(),
        target.id.clone().unwrap_or_default(),
        target.role.clone().unwrap_or_default(),
        target.tag.clone().unwrap_or_default(),
    ];
    for (k, v) in &target.attributes {
        chunks.push(k.clone());
        chunks.push(v.clone());
    }
    chunks.join(" ")
}

fn string_arg<'a>(args: &'a BTreeMap<String, JsonValue>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| args.get(*key).and_then(JsonValue::as_str))
}

fn parse_sensitivity(value: &str) -> Sensitivity {
    match value.to_ascii_lowercase().as_str() {
        "secret" => Sensitivity::Secret,
        "sensitive" => Sensitivity::Sensitive,
        "internal" => Sensitivity::Internal,
        _ => Sensitivity::Public,
    }
}

fn risk_level(score: u8) -> RiskLevel {
    match score {
        0..=24 => RiskLevel::Low,
        25..=49 => RiskLevel::Medium,
        50..=79 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

fn capability_for(
    action: &CanonicalAction,
    resource: &Resource,
    sensitivity: &Sensitivity,
) -> String {
    let domain = resource.domain.as_deref().unwrap_or("local");
    let base = match action {
        CanonicalAction::Navigate => format!("web.navigate:{domain}"),
        CanonicalAction::Read => format!("resource.read:{}", resource.kind),
        CanonicalAction::Write => format!("resource.write:{}", resource.kind),
        CanonicalAction::Execute => "system.execute".to_string(),
        CanonicalAction::Network => format!("network.request:{domain}"),
        CanonicalAction::UiClick => format!("ui.click:{domain}"),
        CanonicalAction::UiType => format!("ui.type:{domain}"),
        CanonicalAction::UiSelect => format!("ui.select:{domain}"),
        CanonicalAction::UiScroll => format!("ui.scroll:{domain}"),
        CanonicalAction::UiHover => format!("ui.hover:{domain}"),
        CanonicalAction::KeyPress => format!("ui.keypress:{domain}"),
        CanonicalAction::Unknown => "unknown".to_string(),
    };
    if matches!(sensitivity, Sensitivity::Secret) {
        format!("{base}:secret")
    } else {
        base
    }
}

fn build_scope(
    resource: &Resource,
    action: &CanonicalAction,
    sensitivity: &Sensitivity,
) -> BTreeMap<String, String> {
    let mut scope = BTreeMap::new();
    scope.insert("resource_kind".to_string(), resource.kind.clone());
    scope.insert("action".to_string(), action.as_str().to_string());
    scope.insert("sensitivity".to_string(), sensitivity.as_str().to_string());
    if let Some(domain) = &resource.domain {
        scope.insert("domain".to_string(), domain.clone());
    }
    if let Some(path) = &resource.path {
        scope.insert("path".to_string(), path.clone());
    }
    if let Some(selector) = &resource.selector {
        scope.insert("selector".to_string(), selector.clone());
    }
    scope
}

impl RawRequest {
    fn from_json(value: &JsonValue) -> Result<Self, NormalizeError> {
        let obj = value
            .as_object()
            .ok_or_else(|| NormalizeError::InvalidJson("root must be an object".to_string()))?;
        Ok(Self {
            request_id: get_string(obj, "request_id"),
            agent_id: get_string(obj, "agent_id"),
            user_id: get_string(obj, "user_id"),
            session_id: get_string(obj, "session_id"),
            timestamp: get_string(obj, "timestamp"),
            source: get_string(obj, "source"),
            task: get_string(obj, "task"),
            observation: obj.get("observation").and_then(RawObservation::from_json),
            action: obj.get("action").and_then(RawAction::from_json),
            tool: obj.get("tool").and_then(RawToolCall::from_json),
            policy_hints: obj
                .get("policy_hints")
                .and_then(JsonValue::as_object)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

impl RawObservation {
    fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_object()?;
        Some(Self {
            url: get_string(obj, "url"),
            title: get_string(obj, "title"),
            viewport: obj
                .get("viewport")
                .and_then(JsonValue::as_object)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

impl RawAction {
    fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_object()?;
        let scroll_delta = obj.get("scroll_delta").and_then(|v| match v {
            JsonValue::Array(items) if items.len() == 2 => {
                Some((items[0].as_i64()?, items[1].as_i64()?))
            }
            _ => None,
        });
        Some(Self {
            op: get_string(obj, "op")?,
            target: obj.get("target").and_then(RawTarget::from_json),
            value: get_string(obj, "value"),
            key: get_string(obj, "key"),
            scroll_delta,
        })
    }
}

impl RawTarget {
    fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_object()?;
        let attributes = obj
            .get("attributes")
            .and_then(JsonValue::as_object)
            .map(|attrs| {
                attrs
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let bbox = obj.get("bbox").and_then(|v| match v {
            JsonValue::Array(items) => Some(items.iter().filter_map(JsonValue::as_f64).collect()),
            _ => None,
        });
        Some(Self {
            css_selector: get_string(obj, "css_selector"),
            xpath: get_string(obj, "xpath"),
            tag: get_string(obj, "tag"),
            role: get_string(obj, "role"),
            text: get_string(obj, "text"),
            aria_label: get_string(obj, "aria_label"),
            name: get_string(obj, "name"),
            id: get_string(obj, "id"),
            bbox,
            attributes,
        })
    }
}

impl RawToolCall {
    fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_object()?;
        Some(Self {
            name: get_string(obj, "name")?,
            args: obj
                .get("args")
                .and_then(JsonValue::as_object)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

fn get_string(obj: &BTreeMap<String, JsonValue>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
}

impl JsonValue {
    fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        if let JsonValue::Object(o) = self {
            Some(o)
        } else {
            None
        }
    }
    fn as_str(&self) -> Option<&str> {
        if let JsonValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    fn as_f64(&self) -> Option<f64> {
        if let JsonValue::Number(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|n| n as i64)
    }
    fn to_compact_json(&self) -> String {
        json_to_string(self, 0, false)
    }
}

impl CanonicalAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Network => "network",
            Self::UiClick => "ui_click",
            Self::UiType => "ui_type",
            Self::UiSelect => "ui_select",
            Self::UiScroll => "ui_scroll",
            Self::UiHover => "ui_hover",
            Self::KeyPress => "key_press",
            Self::Unknown => "unknown",
        }
    }
}
impl Sensitivity {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }
}
impl RiskLevel {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}
impl DecisionHint {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Review => "review",
            Self::Deny => "deny",
        }
    }
}

impl NormalizedRequest {
    pub fn to_json_pretty(&self) -> String {
        json_to_string(&self.to_json_value(), 0, true)
    }
    pub fn to_json_compact(&self) -> String {
        json_to_string(&self.to_json_value(), 0, false)
    }
    fn to_json_value(&self) -> JsonValue {
        let mut o = BTreeMap::new();
        insert_opt(&mut o, "request_id", &self.request_id);
        insert_opt(&mut o, "agent_id", &self.agent_id);
        insert_opt(&mut o, "user_id", &self.user_id);
        insert_opt(&mut o, "session_id", &self.session_id);
        insert_opt(&mut o, "timestamp", &self.timestamp);
        o.insert(
            "canonical_action".to_string(),
            JsonValue::String(self.canonical_action.as_str().to_string()),
        );
        o.insert(
            "capability".to_string(),
            JsonValue::String(self.capability.clone()),
        );
        o.insert("resource".to_string(), self.resource.to_json_value());
        o.insert(
            "scope".to_string(),
            JsonValue::Object(
                self.scope
                    .iter()
                    .map(|(k, v)| (k.clone(), JsonValue::String(v.clone())))
                    .collect(),
            ),
        );
        o.insert(
            "sensitivity".to_string(),
            JsonValue::String(self.sensitivity.as_str().to_string()),
        );
        o.insert(
            "risk_level".to_string(),
            JsonValue::String(self.risk_level.as_str().to_string()),
        );
        o.insert(
            "risk_score".to_string(),
            JsonValue::Number(self.risk_score as f64),
        );
        o.insert(
            "decision_hint".to_string(),
            JsonValue::String(self.decision_hint.as_str().to_string()),
        );
        o.insert(
            "requires_confirmation".to_string(),
            JsonValue::Bool(self.requires_confirmation),
        );
        o.insert(
            "redactions".to_string(),
            JsonValue::Array(
                self.redactions
                    .iter()
                    .map(Redaction::to_json_value)
                    .collect(),
            ),
        );
        o.insert(
            "reasons".to_string(),
            JsonValue::Array(
                self.reasons
                    .iter()
                    .map(|r| JsonValue::String(r.clone()))
                    .collect(),
            ),
        );
        o.insert("provenance".to_string(), self.provenance.to_json_value());
        JsonValue::Object(o)
    }
}

impl Resource {
    fn to_json_value(&self) -> JsonValue {
        let mut o = BTreeMap::new();
        o.insert("kind".to_string(), JsonValue::String(self.kind.clone()));
        o.insert(
            "identifier".to_string(),
            JsonValue::String(self.identifier.clone()),
        );
        insert_opt(&mut o, "url", &self.url);
        insert_opt(&mut o, "domain", &self.domain);
        insert_opt(&mut o, "path", &self.path);
        insert_opt(&mut o, "selector", &self.selector);
        JsonValue::Object(o)
    }
}
impl Redaction {
    fn to_json_value(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            ("field".to_string(), JsonValue::String(self.field.clone())),
            ("reason".to_string(), JsonValue::String(self.reason.clone())),
        ]))
    }
}
impl Provenance {
    fn to_json_value(&self) -> JsonValue {
        let mut o = BTreeMap::new();
        insert_opt(&mut o, "source", &self.source);
        insert_opt(&mut o, "raw_op", &self.raw_op);
        insert_opt(&mut o, "tool_name", &self.tool_name);
        JsonValue::Object(o)
    }
}
fn insert_opt(map: &mut BTreeMap<String, JsonValue>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        map.insert(key.to_string(), JsonValue::String(value.clone()));
    }
}

pub fn parse_json(input: &str) -> Result<JsonValue, NormalizeError> {
    let mut parser = Parser {
        chars: input.chars().collect(),
        pos: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return Err(NormalizeError::InvalidJson(
            "trailing characters".to_string(),
        ));
    }
    Ok(value)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}
impl Parser {
    fn parse_value(&mut self) -> Result<JsonValue, NormalizeError> {
        self.skip_ws();
        match self.peek() {
            Some('n') => {
                self.expect_literal("null")?;
                Ok(JsonValue::Null)
            }
            Some('t') => {
                self.expect_literal("true")?;
                Ok(JsonValue::Bool(true))
            }
            Some('f') => {
                self.expect_literal("false")?;
                Ok(JsonValue::Bool(false))
            }
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some('-') | Some('0'..='9') => self.parse_number().map(JsonValue::Number),
            _ => Err(NormalizeError::InvalidJson("unexpected token".to_string())),
        }
    }
    fn parse_object(&mut self) -> Result<JsonValue, NormalizeError> {
        self.bump();
        let mut obj = BTreeMap::new();
        loop {
            self.skip_ws();
            if self.peek() == Some('}') {
                self.bump();
                break;
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(':')?;
            let value = self.parse_value()?;
            obj.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {
                    self.bump();
                    break;
                }
                _ => return Err(NormalizeError::InvalidJson("expected , or }".to_string())),
            }
        }
        Ok(JsonValue::Object(obj))
    }
    fn parse_array(&mut self) -> Result<JsonValue, NormalizeError> {
        self.bump();
        let mut arr = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(']') {
                self.bump();
                break;
            }
            arr.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {
                    self.bump();
                    break;
                }
                _ => return Err(NormalizeError::InvalidJson("expected , or ]".to_string())),
            }
        }
        Ok(JsonValue::Array(arr))
    }
    fn parse_string(&mut self) -> Result<String, NormalizeError> {
        self.expect('"')?;
        let mut out = String::new();
        while let Some(c) = self.bump() {
            match c {
                '"' => return Ok(out),
                '\\' => match self
                    .bump()
                    .ok_or_else(|| NormalizeError::InvalidJson("unterminated escape".to_string()))?
                {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = (0..4).filter_map(|_| self.bump()).collect();
                        let code = u16::from_str_radix(&hex, 16).map_err(|_| {
                            NormalizeError::InvalidJson("invalid unicode escape".to_string())
                        })?;
                        if let Some(ch) = char::from_u32(code as u32) {
                            out.push(ch);
                        }
                    }
                    _ => return Err(NormalizeError::InvalidJson("invalid escape".to_string())),
                },
                _ => out.push(c),
            }
        }
        Err(NormalizeError::InvalidJson(
            "unterminated string".to_string(),
        ))
    }
    fn parse_number(&mut self) -> Result<f64, NormalizeError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.bump();
        }
        if self.peek() == Some('.') {
            self.bump();
            while matches!(self.peek(), Some('0'..='9')) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.bump();
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.bump();
            }
            while matches!(self.peek(), Some('0'..='9')) {
                self.bump();
            }
        }
        self.chars[start..self.pos]
            .iter()
            .collect::<String>()
            .parse()
            .map_err(|_| NormalizeError::InvalidJson("invalid number".to_string()))
    }
    fn expect_literal(&mut self, literal: &str) -> Result<(), NormalizeError> {
        for expected in literal.chars() {
            self.expect(expected)?;
        }
        Ok(())
    }
    fn expect(&mut self, expected: char) -> Result<(), NormalizeError> {
        match self.bump() {
            Some(c) if c == expected => Ok(()),
            _ => Err(NormalizeError::InvalidJson(format!("expected {expected}"))),
        }
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\n' | '\r' | '\t')) {
            self.bump();
        }
    }
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }
}

fn json_to_string(value: &JsonValue, depth: usize, pretty: bool) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(v) => v.to_string(),
        JsonValue::Number(n) => {
            if n.fract() == 0.0 {
                format!("{:.0}", n)
            } else {
                n.to_string()
            }
        }
        JsonValue::String(s) => quote_json(s),
        JsonValue::Array(items) => {
            if items.is_empty() {
                return "[]".to_string();
            }
            let mut out = String::from("[");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth + 1));
                }
                out.push_str(&json_to_string(item, depth + 1, pretty));
            }
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            out.push(']');
            out
        }
        JsonValue::Object(obj) => {
            if obj.is_empty() {
                return "{}".to_string();
            }
            let mut out = String::from("{");
            for (idx, (k, v)) in obj.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth + 1));
                }
                out.push_str(&quote_json(k));
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                out.push_str(&json_to_string(v, depth + 1, pretty));
            }
            if pretty {
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            out.push('}');
            out
        }
    }
}
fn quote_json(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_navigation_url() {
        let raw = RawRequest {
            action: Some(RawAction {
                op: "NAVIGATE".to_string(),
                value: Some("HTTPS://Example.COM:443/a#frag".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let normalized = normalize(raw).unwrap();
        assert_eq!(normalized.canonical_action, CanonicalAction::Navigate);
        assert_eq!(
            normalized.resource.url.as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(normalized.capability, "web.navigate:example.com");
        assert_eq!(normalized.risk_level, RiskLevel::Low);
    }

    #[test]
    fn marks_password_typing_secret_and_redacted() {
        let raw = RawRequest {
            observation: Some(RawObservation {
                url: Some("https://app.example/login".to_string()),
                ..Default::default()
            }),
            action: Some(RawAction {
                op: "TYPE".to_string(),
                value: Some("correct horse battery staple".to_string()),
                target: Some(RawTarget {
                    css_selector: Some("#password".to_string()),
                    id: Some("password".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let normalized = normalize(raw).unwrap();
        assert_eq!(normalized.sensitivity, Sensitivity::Secret);
        assert_eq!(normalized.decision_hint, DecisionHint::Deny);
        assert_eq!(normalized.redactions.len(), 1);
        assert!(normalized.capability.ends_with(":secret"));
    }

    #[test]
    fn dangerous_click_requires_review() {
        let raw = RawRequest {
            observation: Some(RawObservation {
                url: Some("https://billing.example/settings".to_string()),
                ..Default::default()
            }),
            action: Some(RawAction {
                op: "CLICK".to_string(),
                target: Some(RawTarget {
                    text: Some("Delete workspace".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let normalized = normalize(raw).unwrap();
        assert_eq!(normalized.risk_level, RiskLevel::High);
        assert_eq!(normalized.decision_hint, DecisionHint::Review);
        assert!(normalized.requires_confirmation);
    }

    #[test]
    fn shell_tool_is_critical() {
        let raw = RawRequest {
            tool: Some(RawToolCall {
                name: "shell.exec".to_string(),
                args: BTreeMap::new(),
            }),
            ..Default::default()
        };
        let normalized = normalize(raw).unwrap();
        assert_eq!(normalized.canonical_action, CanonicalAction::Execute);
        assert_eq!(normalized.decision_hint, DecisionHint::Deny);
        assert_eq!(normalized.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn parses_and_normalizes_json() {
        let input = r##"{"request_id":"r1","source":"uia","observation":{"url":"https://example.com/form"},"action":{"op":"CLICK","target":{"css_selector":"#submit","text":"Submit"}}}"##;
        let raw = raw_request_from_json(input).unwrap();
        assert_eq!(raw.request_id.as_deref(), Some("r1"));
        let normalized = normalize(raw).unwrap();
        assert_eq!(normalized.risk_level, RiskLevel::High);
    }
}
