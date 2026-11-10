//! 分层配置：主配置 + `${VAR}` 展开（与 center / evidence 同口径，fail-closed）。
//!
//! 这个服务**不持有**证据桶凭据；它持有的只有「到证据服务的身份」——
//! 租户、scope、敏感度上限。这三项决定 BFF 能要到什么，所以它们只出现在配置里，
//! **不接受**浏览器传参。

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use orion_sec::sec::NoSecConv;
use orion_sec::{SecFileFmt, load_sec_dict, load_secfile_by};
use orion_variate::vars::{EnvChecker, EnvDict, EnvEvaluable, ValueType};
use serde::Deserialize;

const SEC_FILE_ENV: &str = "WIST_FIELD_SEC_FILE";
const CONFIG_ENV: &str = "WIST_FIELD_CONFIG";

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    /// `auth.mode = "cred"` 时必填；`ingress` 时可有可无。
    pub credentials: Option<CredentialsConfig>,
    pub evidence: EvidenceConfig,
    pub atlas: Option<AtlasConfig>,
    pub metrics: Option<MetricsConfig>,
    pub integration: IntegrationConfig,
    /// 业务层：主机集合 → 命名的逻辑单元。空 = 还没做归属记账。
    pub business: Vec<BusinessUnit>,
}

/// 一个业务单元（「这条业务线算谁的产出」）。
///
/// 业务单元 **不是** `app`：`app` 表达用途（这台机器上跑什么），业务单元表达归属
/// （这台机器的开销算到哪条业务上）。归属关系只存在于本配置里，**不下沉到数据面**——
/// agentd / wparse 的 label 契约不需要知道记账口径。
#[derive(Debug, Clone)]
pub struct BusinessUnit {
    pub id: String,
    /// 展示名；配置里留空时用 `id`。
    pub name: String,
    /// 归属主机（`agent` label 的值，形如 `agent-host-<hash>`）。
    pub agents: Vec<String>,
}

/// 展示给运维的「数据面接入」信息。
///
/// 这里**只放公开信息**（写端点、允许的 kind）；站点 token 永远不出现在响应里。
#[derive(Debug, Clone)]
pub struct IntegrationConfig {
    /// 数据面能看到的证据写端点（`http://<内网地址>:<端口>/internal/evidence`）。
    /// 没配就不展示 URL，只展示占位符。
    pub sink_url: Option<String>,
    /// **BFF 视角**的写端点探活地址（容器网络里的地址，通常是 `http://evidence:8080/healthz`）。
    /// 它与 `sink_url` 不是一回事：`sink_url` 是给数据面看的，BFF 到不了。
    pub sink_health_url: Option<String>,
    pub allowed_kinds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
}

/// `cred`：按 `wist-cred` 签发的 token 认证（`Authorization: Bearer wcr_…`），
/// 摘要由 cred 通过 mTLS 推过来；`ingress`：入口（VPN / 堡垒机 / 反代）已认证并注入操作者头。
///
/// **没有「不校验」这一档**：dev 直通曾经存在，但一个计算区界面「默认谁都能进」是不可接受的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Cred,
    Ingress,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub operator_header: String,
}

/// 访问凭据（`wist-cred` 的验证方 `X`）。
#[derive(Debug, Clone)]
pub struct CredentialsConfig {
    /// 接入命令落的 `cred.toml`（identity + verify 两段都以它为准）。
    pub file: PathBuf,
    /// cred 推送摘要的 mTLS 监听（宿主/栈内端口由编排决定）。
    pub listen_addr: String,
    /// 摘要表落盘（**只存 sha256**）。
    pub store_path: PathBuf,
    /// 进入 console 需要的角色（cred 页面签发时选的角色组合里至少要命中一个）。
    pub required_roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    pub base_url: String,
    pub tenant: String,
    pub scopes: Vec<String>,
    pub max_sensitivity: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct AtlasConfig {
    /// 资产拓扑读接口（`/healthz`、`/api/*`）。
    pub base_url: String,
    /// 读接口的令牌（atlas 的 `WIST_ATLAS_TOKEN`）。
    ///
    /// atlas 从 0.3.4 起读接口要 `Authorization: Bearer`；BFF 是唯一会发这个头的调用方
    /// （浏览器只拿 BFF 的令牌）。没配 = 对面没开鉴权（老版本 atlas）。
    pub auth_token: Option<String>,
    /// 数据面能看到的 atlas 写端点（`http://<内网地址>:<端口>/internal/atlas`）。
    /// 与 `integration.sink_url` 同一个意思：给运维 copy，不是 BFF 自己用的地址。
    pub sink_url: Option<String>,
}

/// VictoriaMetrics（或任何兼容的 Prometheus 查询 API）。
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// BFF 视角的查询入口（栈内地址，用于探活与指标页）。
    pub base_url: String,
    /// **数据面视角**的写入端点（`http://<内网地址>:<宿主端口>`）。
    ///
    /// 与 `atlas.sink_url` 同一个意思：给数据面看 / copy 的地址，BFF 自己不去写。
    /// 没配就不展示写入样板 —— 不编造一个假地址，那正是这份配置存在的理由。
    pub write_url: Option<String>,
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => match std::env::var_os(CONFIG_ENV).filter(|value| !value.is_empty()) {
                Some(value) => PathBuf::from(value),
                None => PathBuf::from("field-api.toml"),
            },
        };
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read config {}", path.display()))?;
        let raw: RawConfig =
            toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
        let env = secret_dict()?;
        raw.resolve(&env)
    }
}

fn expand(env: &EnvDict, value: &str) -> anyhow::Result<String> {
    let expanded: String = value.to_string().env_eval(env);
    if expanded.needs_env_eval() {
        bail!(
            "unresolved environment variable(s) in {value:?}: {}",
            expanded.list_env_vars().join(", ")
        );
    }
    Ok(expanded)
}

/// 给**不受 `RawConfig` 管的文件**（如 `cred.toml`）用的展开：`${SEC_…}` / `${ENV}`。
/// `cred.toml` 是 cred-peer 的配置格式，不过 BFF 的 `RawConfig`；但里面的秘密
/// （`[init].setup_code`）必须同样走密钥文件，而不是写死在栈模板里。
pub(crate) fn expand_secret(value: &str) -> Result<String, String> {
    let env = secret_dict().map_err(|err| format!("{err}"))?;
    expand(&env, value).map_err(|err| format!("{err}"))
}

fn secret_dict() -> anyhow::Result<EnvDict> {
    let mut dict = match std::env::var_os(SEC_FILE_ENV).filter(|path| !path.is_empty()) {
        Some(path) => load_sec_file(Path::new(&path))?,
        None => load_sec_dict().map_err(|err| anyhow::anyhow!("failed to load secrets: {err}"))?,
    };
    for (key, value) in std::env::vars() {
        dict.insert(key, ValueType::from(value.as_str()));
    }
    Ok(dict)
}

fn load_sec_file(path: &Path) -> anyhow::Result<EnvDict> {
    if !path.exists() {
        bail!(
            "secrets file not found: {} ({SEC_FILE_ENV})",
            path.display()
        );
    }
    let space = load_secfile_by(path.to_path_buf(), SecFileFmt::Yaml)
        .map_err(|err| anyhow::anyhow!("failed to load secrets {}: {err}", path.display()))?;
    let mut dict = EnvDict::new();
    for (key, value) in space.no_sec() {
        dict.insert(key, value);
    }
    Ok(dict)
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    auth: RawAuth,
    #[serde(default)]
    credentials: Option<RawCredentials>,
    evidence: RawEvidence,
    #[serde(default)]
    atlas: Option<RawAtlas>,
    #[serde(default)]
    metrics: Option<RawMetrics>,
    #[serde(default)]
    integration: RawIntegration,
    #[serde(default)]
    business: RawBusiness,
}

#[derive(Debug, Default, Deserialize)]
struct RawBusiness {
    #[serde(default)]
    units: Vec<RawBusinessUnit>,
}

#[derive(Debug, Deserialize)]
struct RawBusinessUnit {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    agents: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawIntegration {
    #[serde(default)]
    sink_url: String,
    #[serde(default)]
    sink_health_url: String,
    #[serde(default = "default_integration_kinds")]
    allowed_kinds: Vec<String>,
}

impl Default for RawIntegration {
    fn default() -> Self {
        Self {
            sink_url: String::new(),
            sink_health_url: String::new(),
            allowed_kinds: default_integration_kinds(),
        }
    }
}

fn default_integration_kinds() -> Vec<String> {
    vec!["investigation_report".to_string()]
}

#[derive(Debug, Deserialize)]
struct RawServer {
    #[serde(default = "default_listen")]
    listen_addr: String,
}

impl Default for RawServer {
    fn default() -> Self {
        Self {
            listen_addr: default_listen(),
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}

#[derive(Debug, Deserialize)]
struct RawCredentials {
    /// 接入命令落的 `cred.toml`（必填）。
    file: String,
    #[serde(default = "default_credentials_listen")]
    listen_addr: String,
    #[serde(default = "default_credentials_store")]
    store_path: String,
    #[serde(default = "default_required_roles")]
    required_roles: Vec<String>,
}

fn default_credentials_listen() -> String {
    "0.0.0.0:3103".to_string()
}

fn default_credentials_store() -> String {
    "state/credentials.json".to_string()
}

fn default_required_roles() -> Vec<String> {
    vec!["read".to_string()]
}

#[derive(Debug, Deserialize)]
struct RawAuth {
    #[serde(default = "default_auth_mode")]
    mode: String,
    #[serde(default = "default_operator_header")]
    operator_header: String,
}

impl Default for RawAuth {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            operator_header: default_operator_header(),
        }
    }
}

fn default_auth_mode() -> String {
    // 默认走凭据：没配 `[credentials]` 就在启动时报错，而不是默默退化成「谁都能进」。
    "cred".to_string()
}

fn default_operator_header() -> String {
    "x-field-operator".to_string()
}

#[derive(Debug, Deserialize)]
struct RawEvidence {
    base_url: String,
    tenant: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_max_sensitivity")]
    max_sensitivity: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_scopes() -> Vec<String> {
    vec!["evidence:read".to_string()]
}

fn default_max_sensitivity() -> String {
    "paths".to_string()
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Deserialize)]
struct RawAtlas {
    base_url: String,
    #[serde(default)]
    auth_token: String,
    #[serde(default)]
    sink_url: String,
}

#[derive(Debug, Deserialize)]
struct RawMetrics {
    base_url: String,
    #[serde(default)]
    write_url: String,
}

impl RawConfig {
    fn resolve(self, env: &EnvDict) -> anyhow::Result<Config> {
        let mode = match self.auth.mode.trim() {
            "cred" => AuthMode::Cred,
            "ingress" => AuthMode::Ingress,
            other => bail!("auth.mode must be cred|ingress, got {other:?}"),
        };
        if mode == AuthMode::Cred && self.credentials.is_none() {
            // fail-closed：说好了走凭据却没给材料，不能默默降级成
            // 「ingress 但又没有入口」那种 401 满地跑的半吊子状态。
            bail!("auth.mode = cred requires a [credentials] section (file = <cred.toml>)");
        }
        if self.auth.operator_header.trim().is_empty() {
            bail!("auth.operator_header must not be empty");
        }
        if self.evidence.tenant.trim().is_empty() {
            bail!("evidence.tenant must not be empty");
        }
        if self.evidence.scopes.is_empty() {
            bail!("evidence.scopes must list at least one scope");
        }
        if self.evidence.timeout_secs == 0 {
            bail!("evidence.timeout_secs must be > 0");
        }
        let expires = self.evidence.max_sensitivity.trim().to_ascii_lowercase();
        if !matches!(
            expires.as_str(),
            "metrics"
                | "paths"
                | "commandlines"
                | "identities"
                | "secret_metadata"
                | "security_posture"
        ) {
            bail!(
                "evidence.max_sensitivity must be one of metrics|paths|commandlines|identities|secret_metadata|security_posture, got {:?}",
                self.evidence.max_sensitivity
            );
        }

        Ok(Config {
            server: ServerConfig {
                listen_addr: self.server.listen_addr,
            },
            auth: AuthConfig {
                mode,
                operator_header: self.auth.operator_header,
            },
            credentials: match self.credentials {
                Some(raw) => {
                    if raw.file.trim().is_empty() {
                        bail!("credentials.file must point at the cred.toml from the join command");
                    }
                    if raw.required_roles.is_empty() {
                        bail!("credentials.required_roles must list at least one role");
                    }
                    Some(CredentialsConfig {
                        file: expand(env, &raw.file)?.into(),
                        listen_addr: expand(env, &raw.listen_addr)?,
                        store_path: expand(env, &raw.store_path)?.into(),
                        required_roles: raw.required_roles,
                    })
                }
                None => None,
            },
            evidence: EvidenceConfig {
                base_url: expand(env, &self.evidence.base_url)?,
                tenant: self.evidence.tenant,
                scopes: self.evidence.scopes,
                max_sensitivity: expires,
                timeout_secs: self.evidence.timeout_secs,
            },
            atlas: match self.atlas {
                Some(atlas) => Some(AtlasConfig {
                    base_url: expand(env, &atlas.base_url)?,
                    auth_token: if atlas.auth_token.trim().is_empty() {
                        None
                    } else {
                        Some(expand(env, &atlas.auth_token)?)
                    },
                    sink_url: if atlas.sink_url.trim().is_empty() {
                        None
                    } else {
                        Some(expand(env, &atlas.sink_url)?)
                    },
                }),
                None => None,
            },
            metrics: match self.metrics {
                Some(metrics) if !metrics.base_url.trim().is_empty() => Some(MetricsConfig {
                    base_url: expand(env, &metrics.base_url)?,
                    write_url: if metrics.write_url.trim().is_empty() {
                        None
                    } else {
                        Some(expand(env, &metrics.write_url)?)
                    },
                }),
                _ => None,
            },
            integration: IntegrationConfig {
                sink_url: if self.integration.sink_url.trim().is_empty() {
                    None
                } else {
                    Some(expand(env, &self.integration.sink_url)?)
                },
                sink_health_url: if self.integration.sink_health_url.trim().is_empty() {
                    None
                } else {
                    Some(expand(env, &self.integration.sink_health_url)?)
                },
                allowed_kinds: self.integration.allowed_kinds,
            },
            business: resolve_business(self.business)?,
        })
    }
}

fn resolve_business(raw: RawBusiness) -> anyhow::Result<Vec<BusinessUnit>> {
    let mut ids: HashSet<String> = HashSet::new();
    // 一台主机只能属于一个业务：跨业务共会导致投入（CPU / 内存 / 磁盘）重复计账。
    let mut owners: BTreeMap<String, String> = BTreeMap::new();
    let mut units = Vec::with_capacity(raw.units.len());
    for unit in raw.units {
        let id = unit.id.trim().to_string();
        if id.is_empty() {
            bail!("business.units[].id must not be empty");
        }
        if !ids.insert(id.clone()) {
            bail!("duplicate business unit id {id:?}");
        }
        let name = match unit.name.trim() {
            "" => id.clone(),
            name => name.to_string(),
        };
        let mut agents: Vec<String> = Vec::with_capacity(unit.agents.len());
        for agent in unit.agents {
            let agent = agent.trim().to_string();
            if agent.is_empty() || agents.contains(&agent) {
                continue;
            }
            if let Some(owner) = owners.get(&agent) {
                bail!("agent {agent:?} is assigned to both business units {owner:?} and {id:?}");
            }
            owners.insert(agent.clone(), id.clone());
            agents.push(agent);
        }
        units.push(BusinessUnit { id, name, agents });
    }
    Ok(units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> anyhow::Result<Config> {
        let raw: RawConfig = toml::from_str(raw)?;
        raw.resolve(&EnvDict::new())
    }

    #[test]
    fn defaults_are_cred_read_only() {
        let config = parse(
            r#"
            [credentials]
            file = "/etc/wist-field-api/cred/cred.toml"

            [evidence]
            base_url = "http://127.0.0.1:8443"
            tenant = "t-001"
            "#,
        )
        .expect("minimal config should parse");
        // 默认走凭据，不是「不校验」：没有 token 就进不来。
        assert_eq!(config.auth.mode, AuthMode::Cred);
        let credentials = config.credentials.as_ref().expect("credentials");
        assert_eq!(credentials.required_roles, vec!["read"]);
        assert_eq!(config.auth.operator_header, "x-field-operator");
        assert_eq!(config.evidence.scopes, vec!["evidence:read"]);
        assert_eq!(config.evidence.max_sensitivity, "paths");
        assert!(config.atlas.is_none());
        assert!(config.integration.sink_url.is_none());
        assert!(config.integration.sink_health_url.is_none());
    }

    #[test]
    fn cred_mode_without_credentials_is_rejected() {
        let error = parse(
            r#"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"
            "#,
        )
        .expect_err("cred without materials must fail");
        assert!(
            error
                .to_string()
                .contains("requires a [credentials] section"),
            "{error}"
        );
    }

    #[test]
    fn ingress_mode_does_not_need_credentials() {
        let config = parse(
            r#"
            [auth]
            mode = "ingress"

            [evidence]
            base_url = "http://x"
            tenant = "t-001"
            "#,
        )
        .expect("ingress is still supported behind a proxy");
        assert_eq!(config.auth.mode, AuthMode::Ingress);
        assert!(config.credentials.is_none());
    }

    #[test]
    fn unknown_auth_mode_is_rejected() {
        let error = parse(
            r#"
            [auth]
            mode = "open"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"
            "#,
        )
        .expect_err("unknown auth mode must fail");
        assert!(error.to_string().contains("auth.mode must be cred|ingress"));
    }

    #[test]
    fn unknown_sensitivity_is_rejected() {
        let error = parse(
            r#"
            [auth]
            mode = "ingress"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"
            max_sensitivity = "everything"
            "#,
        )
        .expect_err("unknown sensitivity must fail");
        assert!(error.to_string().contains("max_sensitivity"));
    }

    #[test]
    fn unresolved_placeholder_is_rejected() {
        let error = parse(
            r#"
            [auth]
            mode = "ingress"
            [evidence]
            base_url = "${SEC_EVIDENCE_URL}"
            tenant = "t-001"
            "#,
        )
        .expect_err("unresolved env must fail");
        assert!(
            error
                .to_string()
                .contains("unresolved environment variable")
        );
    }

    #[test]
    fn business_units_default_to_the_id_and_drop_blank_agents() {
        let config = parse(
            r#"
            [auth]
            mode = "ingress"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"

            [[business.units]]
            id = "billing"
            agents = ["agent-host-a", " ", "agent-host-b"]
            "#,
        )
        .expect("business units are optional");
        assert_eq!(config.business.len(), 1);
        assert_eq!(config.business[0].name, "billing");
        assert_eq!(
            config.business[0].agents,
            vec!["agent-host-a", "agent-host-b"]
        );
    }

    #[test]
    fn one_agent_cannot_belong_to_two_business_units() {
        let error = parse(
            r#"
            [auth]
            mode = "ingress"
            [evidence]
            base_url = "http://x"
            tenant = "t-001"

            [[business.units]]
            id = "billing"
            agents = ["agent-host-a"]

            [[business.units]]
            id = "search"
            agents = ["agent-host-a"]
            "#,
        )
        .expect_err("shared hosts double-count投入, so they are rejected");
        assert!(error.to_string().contains("assigned to both"), "{error}");
    }
}
