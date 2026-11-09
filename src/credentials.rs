//! 访问凭据（`wist-cred`）：本服务是验证方（X）。
//!
//! 两张面，两个职责：
//!
//! | 面 | 做什么 |
//! |---|---|
//! | mTLS 收数监听（`credentials.listen_addr`，默认 `3103`） | 收 cred 推来的 `{digest, subject, roles, expires_at, signature}`，只落 sha256 |
//! | 业务监听（`server.listen_addr`） | 校验 `Authorization: Bearer wcr_…` → 角色 → 401 / 403 |
//!
//! **材料只读 `cred.toml`**：identity（服务器证书 / 私钥 / 客户端 CA）与 verify（audience /
//! 签发方白名单 / 签名要求 / 角色词汇表）都由接入命令写入。本服务只在主配置里写一句
//! `credentials.file = <那个文件>`，不把里面的值再抄一遍 —— 抄一遍就一定会漂。
//!
//! 与 `wist-center` 的接入（`src/credentials.rs`）是同一套做法：
//! 启动期就把 TLS 建好，证书缺失 / 链不对就**拒绝启动**，不会出现
//! 「业务面只认凭据、凭据 listener 起不来」的半启用状态。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use wist_cred_peer::{Config as PeerConfig, IdentityFiles, InitConfig, Peer};

use crate::config::CredentialsConfig;

/// `cred.toml` 的结构。
///
/// **两种形态**：
/// - 接入命令写好的（`[identity]` + `[verify]`）：与以前一样，启动即就绪；
/// - 自注册的（`[init]` + `[publish]` + `[verify]`，**没有** `[identity]`）：首次启动时
///   只挂 `/__init`，由本服务自己向 cred 注册并把材料写到默认位置。
#[derive(Debug, Deserialize)]
struct CredFile {
    #[serde(default)]
    identity: Option<IdentitySection>,
    #[serde(default)]
    verify: VerifySection,
    #[serde(default)]
    init: Option<InitSection>,
    #[serde(default)]
    publish: Option<PublishSection>,
}

/// 自注册（初始化页）的配置。
///
/// 字符串字段都支持 `${VAR}`（由 `expand_secret` 展开：密钥文件 + 进程环境）——
/// 栈靠变量切信任锚与开关，而不是让人改这份文件。
#[derive(Debug, Deserialize)]
struct InitSection {
    /// 部署生成的秘密：证明“我有权给这台机器指定 cred 地址”。
    setup_code: String,
    /// cred 注册入口；不给就由用户在初始化页里填。
    #[serde(default)]
    cred_url: Option<String>,
    /// 信任锚（入口的自签 CA）；配了就不靠人眼看指纹。空串 = 没配。
    #[serde(default)]
    ca_file: Option<String>,
    #[serde(default)]
    insecure_tls: Option<Boolish>,
}

/// 本机在 cred 眼里的收数地址（**部署事实**，由栈渲染，不由命令行给）。
#[derive(Debug, Deserialize)]
struct PublishSection {
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct IdentitySection {
    /// 由 CA-S 签的服务器证书。
    cert: PathBuf,
    /// 本机生成的私钥（0600）。
    key: PathBuf,
    /// CA-I 公开证书：用来验 cred 出示的客户端证书。
    client_ca: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct VerifySection {
    /// 本服务的名字；凭据的 `audience` 不等于它就拒。
    #[serde(default)]
    audience: String,
    /// 签发方身份白名单（客户端证书的 `id`），通常就是 `wist-cred`。
    #[serde(default)]
    allowed_issuers: Vec<String>,
    /// 记录必须带签发方 Ed25519 签名。
    #[serde(default)]
    require_signature: Option<Boolish>,
    /// 签发方公钥（一行一把，轮换期可两把）。
    #[serde(default)]
    issuer_public_key_file: Option<PathBuf>,
    /// 本服务认的角色词汇表（cred 侧只能在里面选）。
    #[serde(default)]
    roles: Vec<String>,
}

/// 布尔值：TOML 里可以写 `true`，也可以写 `"${VAR}"`（栈用变量切换）。
///
/// 字符串按展开后的 `true/false|1/0|yes/no|on/off` 解析；展开失败或值不认识都是**启动期错误** ——
/// 不让“变量没渲染”退化成“默认关掉一个安全开关”。
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Boolish {
    Bool(bool),
    Text(String),
}

impl Boolish {
    fn resolve(&self, field: &str) -> Result<bool, String> {
        match self {
            Self::Bool(value) => Ok(*value),
            Self::Text(raw) => {
                let expanded = crate::config::expand_secret(raw)?;
                match expanded.trim().to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => Ok(true),
                    "false" | "0" | "no" | "off" => Ok(false),
                    other => Err(format!(
                        "{field}: expected true|false (optionally via ${{VAR}}), got {other:?}"
                    )),
                }
            }
        }
    }
}

/// 装配好的凭据运行时。
pub struct CredentialRuntime {
    peer: Arc<Peer>,
    listen: SocketAddr,
    /// 材料齐备时构建好的 mTLS 配置；`None` = 未初始化（等 `/__init` 写完材料）。
    tls: Option<rustls::ServerConfig>,
    /// 进入本服务需要的角色（本服务自己的决定，不来自 cred.toml）。
    required_roles: Vec<String>,
    /// 收数 listener 是否还在跑。`spawn_listener` 置位，退出时清掉；
    /// 它挂了不会影响已登记的旧凭据，但「新凭据推不进来」必须能在页面上看到。
    listener_alive: Arc<std::sync::atomic::AtomicBool>,
    /// 启动时材料就在（所以 listener 用的是启动时加载的那套证书）。
    /// 它的用处只有一个：识别「运行中把材料删了」——那时 `is_initialized()` 已经是 false，
    /// 但 listener 还拿旧证书在跑，两个事实必须能同时被看到。
    serving_loaded_tls: bool,
    /// 本次启动**没有**开强制验签，因为启动时公钥还不存在（自注册之前）。
    /// 注册完成后必须重启才生效 —— 这是个“正运行时处于降级状态”的事实，得能看见。
    signature_deferred: bool,
}

impl std::fmt::Debug for CredentialRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRuntime")
            .field("audience", &self.peer.config().audience)
            .field("listen", &self.listen)
            .field("registered", &self.peer.registered())
            .field("required_roles", &self.required_roles)
            .finish()
    }
}

impl CredentialRuntime {
    /// 校验一次 bearer token：`Ok` 带主体与角色，`Err` 带对外错误码。
    pub fn verify(&self, token: &str) -> Result<Caller, VerifyError> {
        let credential = match self.peer.verify(token) {
            Ok(credential) => credential,
            Err(err) => {
                // 对外不区分原因（不做 token 枚举接口），但**日志里要能看出是哪一种**：
                // 大半夜查「令牌突然全失效」时，`token_expired` 和 `invalid_token` 是两个故事。
                // 摘要表读失败（磁盘 / 权限）不是「令牌不对」，不能让所有人去重新登录。
                if matches!(err, wist_auth::credential::CredentialError::Store(_)) {
                    log::error!("event=FieldCredentialStore code={} {err:?}", err.code());
                    return Err(VerifyError::StoreUnavailable);
                }
                log::debug!("event=FieldCredentialRejected code={}", err.code());
                return Err(VerifyError::Invalid);
            }
        };
        // 认证通过、授权不足是 403；对外不区分具体失败原因（不做 token 枚举接口）。
        if !credential
            .roles
            .iter()
            .any(|role| self.required_roles.iter().any(|required| required == role))
        {
            log::warn!(
                "event=FieldForbidden subject={} credential_id={} roles={:?} required={:?}",
                credential.subject,
                credential.credential_id,
                credential.roles,
                self.required_roles,
            );
            return Err(VerifyError::RoleRequired);
        }
        Ok(Caller {
            subject: credential.subject.clone(),
            roles: credential.roles.clone(),
        })
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// 进本服务需要的角色（登录端点的角色闸门用它）。
    pub fn required_roles(&self) -> &[String] {
        &self.required_roles
    }

    /// 本服务作为 cred 验证方的运行时（自注册路由要它）。
    pub fn peer(&self) -> Arc<Peer> {
        Arc::clone(&self.peer)
    }

    /// 材料是否齐备。由 `cred-peer` 推导（三件文件），不额外存状态。
    pub fn is_initialized(&self) -> bool {
        wist_cred_peer::init_state(self.peer.config()) == wist_cred_peer::InitState::Initialized
    }

    /// 本次启动是否因为“公钥还没随注册下发”而暂时没验签。
    pub fn signature_deferred(&self) -> bool {
        self.signature_deferred
    }

    /// 启动时材料就在（listener 用的是启动时加载的证书）。
    pub fn serving_loaded_tls(&self) -> bool {
        self.serving_loaded_tls
    }

    /// 已登记的凭据条数（= 目前能通过认证的 token 数）。
    pub fn registered(&self) -> usize {
        self.peer.registered()
    }

    /// 启动加载时被丢弃的条数（磁盘被改过 / 签名密钥换过）。
    pub fn rejected_on_load(&self) -> usize {
        self.peer.rejected_on_load()
    }

    pub fn listener_alive(&self) -> bool {
        self.listener_alive
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct Caller {
    pub subject: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// 没带 token / token 不认识 / 过期 / 撤销 / audience 不符。
    Invalid,
    /// token 本身有效，但角色不够。
    RoleRequired,
    /// 摘要表读不了（磁盘 / 权限）—— 这是服务端故障，不是「令牌不对」。
    StoreUnavailable,
}

/// 按主配置装配。启用但材料不成立 → 启动期直接失败（fail-fast）。
pub fn build(config: &CredentialsConfig) -> Result<CredentialRuntime, String> {
    let file = &config.file;
    let text = std::fs::read_to_string(file)
        .map_err(|err| format!("read credentials.file {}: {err}", file.display()))?;
    let cred: CredFile = toml::from_str(&text)
        .map_err(|err| format!("parse credentials.file {}: {err}", file.display()))?;

    // cred.toml 里的相对路径按**该文件所在目录**解（接入命令就是按这个约定写的）。
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    // 没有 `[identity]` 但有 `[init]`：材料还没写，用接入命令的默认落点
    // （必须传给 cred-peer，否则它会把“没配 identity”当成“已就绪”）。
    let identity = match (&cred.identity, &cred.init) {
        (Some(identity), _) => IdentityFiles {
            cert: base.join(&identity.cert),
            key: base.join(&identity.key),
            client_ca: base.join(&identity.client_ca),
        },
        (None, Some(_)) => IdentityFiles {
            cert: base.join("server.crt"),
            key: base.join("server.key"),
            client_ca: base.join("client-ca.pem"),
        },
        (None, None) => {
            return Err(format!(
                "{}: neither [identity] nor [init] is present — the service can neither serve \
                 credentials nor register itself",
                file.display()
            ));
        }
    };
    let cert = identity.cert.clone();
    let key = identity.key.clone();
    let client_ca = identity.client_ca.clone();

    // audience 支持 `${…}`：认证系统名是**部署事实**（cred 侧那个 peer 叫什么，这里就得叫什么），
    // 不同站点/认证系统不一样，而现场不该为一个名字去改这份文件。
    // 占位符解不开 → 启动期就报，不静默拿占位符当名字（那会让 cred 的推送永远 400）。
    let audience = crate::config::expand_secret(&cred.verify.audience)?;
    if audience.trim().is_empty() {
        return Err(format!(
            "{}: [verify].audience is missing (re-run the join command)",
            file.display()
        ));
    }
    if cred.verify.allowed_issuers.is_empty() {
        return Err(format!(
            "{}: [verify].allowed_issuers is empty — nothing could ever push credentials",
            file.display()
        ));
    }
    if cred.verify.roles.is_empty() {
        return Err(format!(
            "{}: [verify].roles is empty — every role would be dropped",
            file.display()
        ));
    }
    for required in &config.required_roles {
        if !cred.verify.roles.iter().any(|role| role == required) {
            return Err(format!(
                "credentials.required_roles contains {required:?}, which is not listed in \
                 [verify].roles of {}",
                file.display()
            ));
        }
    }

    let mut require_signature = match &cred.verify.require_signature {
        Some(value) => value.resolve("[verify].require_signature")?,
        None => false,
    };

    let listen: SocketAddr = config
        .listen_addr
        .parse()
        .map_err(|err| format!("credentials.listen_addr {:?}: {err}", config.listen_addr))?;

    let client_ca_pem = std::fs::read_to_string(&client_ca);
    // 三件都在 = 已初始化（与 `wist-cred-peer::init_state` 同一个判据）。
    let initialized = cert.is_file() && key.is_file() && client_ca_pem.is_ok();
    // 三件都在 → 启动即就绪；缺就等 `/__init`（但那就必须配了 `[init]`）。
    let tls = match (&client_ca_pem, &cred.init) {
        (Ok(pem), _) if cert.is_file() && key.is_file() => Some(
            // 严格 mTLS：cred 必须出示 CA-I 签的客户端证书，否则连不上来。
            wist_pki::tls::server_config_mtls(&cert, &key, pem, false)?,
        ),
        // 证书/私钥都在、只有 client CA 读不了（权限/损坏）：这是**配置故障**，
        // 不能当成“还没初始化”混过去 —— cred-peer 会认为已初始化，于是既不会开
        // `/__init`（409），listener 又起不来，现场表现成“一切正常但推不进来”。
        (Err(err), _) if cert.is_file() && key.is_file() => {
            return Err(format!(
                "{}: server cert/key are present but the client CA is unreadable ({err}); \
                 fix the file (or remove all three to re-register)",
                client_ca.display()
            ));
        }
        (_, Some(_)) => None,
        (Err(err), None) => {
            return Err(format!(
                "{}: credentials are absent and [init] is not configured ({err})",
                client_ca.display()
            ));
        }
        (Ok(_), None) => {
            return Err(format!(
                "{}: server certificate or key is missing and [init] is not configured",
                file.display()
            ));
        }
    };

    // 验签公钥是**自注册时随 bundle 下发**的。所以“未初始化 + 强制验签 + 公钥还没到”
    // 不能当配置错误：那会形成启动死锁 —— 进程起不来，就永远打不开 `/__init`。
    // 这一档只允许在**未初始化**时出现，而且必须**显式告警 + 在健康页面上写出来**；
    // 一旦材料齐备（重启后）就恢复强制验签，缺公钥仍然拒启动（fail-closed）。
    let key_file = cred
        .verify
        .issuer_public_key_file
        .as_ref()
        .map(|path| base.join(path));
    let key_ready = key_file.as_ref().is_none_or(|path| path.is_file());
    let mut signature_deferred = false;
    if require_signature && !initialized && !key_ready {
        log::warn!(
            "credentials: [verify].require_signature = true, but no issuer public key at {} — \
             starting WITHOUT signature verification: the key is delivered with the bundle during \
             self-registration (/__init), so it cannot exist yet. Restart this service after \
             registering to enforce it",
            key_file
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unset>".to_string())
        );
        require_signature = false;
        signature_deferred = true;
    }

    let endpoint = match &cred.publish {
        Some(publish) => {
            // 同样要展开：`https://${FIELD_API_ADVERTISE_HOST}:${CREDENTIALS_HOST_PORT}/…`。
            // 不展开的后果很隐蔽 —— 占位符能当一个“主机名”用，证书真能签出来，
            // 直到 cred 拨号才失败（而且错在对方）。
            let expanded = crate::config::expand_secret(&publish.endpoint)?;
            if expanded.trim().is_empty() {
                String::new()
            } else {
                expanded
            }
        }
        None => String::new(),
    };

    let mut peer_config = PeerConfig::new(audience, &config.store_path)
        .known_roles(cred.verify.roles.iter().cloned())
        .require_signature(require_signature)
        // 自注册要靠它推导状态（材料齐不齐）与上报地址。
        .identity(identity)
        .publish_endpoint(endpoint);
    if let Some(init) = &cred.init {
        // 信任锚：可能是 `${FIELD_API_CRED_CA_FILE}`，也可能没配（空串）。
        let ca_file = match &init.ca_file {
            Some(raw) => {
                let expanded = crate::config::expand_secret(raw)?;
                let trimmed = expanded.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(base.join(trimmed))
                }
            }
            None => None,
        };
        let insecure_tls = match &init.insecure_tls {
            Some(value) => value.resolve("[init].insecure_tls")?,
            None => false,
        };
        peer_config = peer_config.init(InitConfig {
            // `cred.toml` 不是 BFF 的 RawConfig，但秘密仍走同一个密钥文件：
            // `setup_code = "${SEC_CONSOLE_PEER_SETUP_CODE}"`。
            setup_code: crate::config::expand_secret(&init.setup_code)?,
            cred_url: match &init.cred_url {
                Some(value) => Some(crate::config::expand_secret(value)?),
                None => None,
            },
            ca_file,
            insecure_tls,
        });
    }
    for issuer in &cred.verify.allowed_issuers {
        peer_config = peer_config.allow_issuer(issuer.clone());
    }
    if let Some(path) = &cred.verify.issuer_public_key_file {
        let path = base.join(path);
        for key in load_issuer_keys(&path, require_signature)? {
            peer_config = peer_config.issuer_public_key(key);
        }
    }

    let peer = Peer::open(peer_config).map_err(|err| format!("{}: {err}", file.display()))?;
    if peer.rejected_on_load() > 0 {
        // 磁盘上的记录被改过 / 签名密钥换过：已被丢弃，但必须让运维看见。
        log::error!(
            "credentials: {} authorization record(s) were rejected on load \
             (invalid signature, missing key, or malformed entry)",
            peer.rejected_on_load()
        );
    }
    if peer.registered() == 0 {
        // 一个都没登记：不是“正常但为空”，而是“还没人推过来”。
        // 最常见的两个原因：peer 没登记 endpoint（控制台 / 种子里没填地址），
        // 或 cred 到不了这个 listener（端口只绑了回环）。
        log::warn!(
            "credentials: 0 credentials registered for audience {:?}; \
             no one has pushed yet — check the peer has a registered endpoint and \
             that wist-cred can reach {} with a CA-S signed server certificate",
            peer.config().audience,
            listen
        );
    }

    Ok(CredentialRuntime {
        peer,
        listen,
        serving_loaded_tls: tls.is_some(),
        tls,
        signature_deferred,
        required_roles: config.required_roles.clone(),
        listener_alive: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}

/// 起收数监听（mTLS）。与业务监听并行跑，互不影响。
///
/// 材料齐备 → 立即起；未初始化（配了 `[init]`）→ **等材料写完**再起：
/// 初始化页落盘之后不需要重启进程。
pub fn spawn_listener(runtime: Arc<CredentialRuntime>) {
    let listen = runtime.listen;
    let peer = Arc::clone(&runtime.peer);
    let tls = runtime.tls.clone();
    let files = peer.config().identity.clone();
    let alive = Arc::clone(&runtime.listener_alive);
    // 未初始化时也置位：`/api/health` 先看 `is_initialized()`（会先报“尚未初始化”），
    // 而 `serve_when_ready` 每 500ms 看一眼材料，所以“说在跑”最多乐观半秒。
    alive.store(true, std::sync::atomic::Ordering::Relaxed);
    let waiting = tls.is_none() && files.is_some();
    tokio::spawn(async move {
        let result = match (tls, files) {
            (Some(config), _) => {
                let app = peer.router();
                wist_cred_peer::serve_router(app, listen, config).await
            }
            (None, Some(files)) => {
                wist_cred_peer::serve_when_ready(
                    peer.clone(),
                    listen,
                    wist_cred_peer::TlsFiles {
                        cert: files.cert,
                        key: files.key,
                        client_ca: files.client_ca,
                    },
                )
                .await
            }
            (None, None) => {
                log::error!("credentials listener on {listen} has no identity paths configured");
                Ok(())
            }
        };
        if let Err(err) = result {
            // 这个 listener 挂了只影响「新凭据能不能推进来」，已登记的摘要仍然有效；
            // 所以记错误而不是把整个进程带下去 —— 但状态要落下来，让 /api/health 能看见。
            log::error!("credentials listener on {listen} stopped: {err}");
        }
        alive.store(false, std::sync::atomic::Ordering::Relaxed);
    });
    if waiting {
        // 与 `/api/health` 的说法一致：先等材料（`/__init` 写完就自己起来）。
        log::warn!(
            "credentials listener on {listen} is waiting for the self-registration materials \
             (open /__init on this service); nothing is listening yet"
        );
    } else {
        log::info!("credentials listener on {listen} (mTLS, push-only)");
    }
}

/// 读签发方公钥：一行一把（轮换期可同时信任新旧两把）。
fn load_issuer_keys(path: &Path, required: bool) -> Result<Vec<Vec<u8>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if !required => {
            // 没开验签时“公钥还没下发”是**正常状态**（自注册之前 / 这台部署不验签），
            // 用 warn 会在每个新部署的启动日志里制造一条假问题；只有“文件在但读不了”才值得说。
            if path.exists() {
                log::warn!(
                    "credentials: issuer public key {} is not readable ({err}); \
                     signature verification is disabled",
                    path.display()
                );
            } else {
                log::debug!(
                    "credentials: no issuer public key at {} yet; signature verification is off",
                    path.display()
                );
            }
            return Ok(Vec::new());
        }
        Err(err) => return Err(format!("read {}: {err}", path.display())),
    };
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let bytes = hex::decode(line)
            .map_err(|err| format!("{}: issuer public key is not hex: {err}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!(
                "{}: issuer public key must be 32 bytes, got {}",
                path.display(),
                bytes.len()
            ));
        }
        keys.push(bytes);
    }
    if keys.is_empty() && required {
        return Err(format!("{} contains no public key", path.display()));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_keys_are_one_per_line() {
        let dir = std::env::temp_dir().join(format!(
            "wist-field-api-cred-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("issuer-signing.pub");
        std::fs::write(&path, format!("{}\n{}\n", "aa".repeat(32), "bb".repeat(32)))
            .expect("write key");
        let keys = load_issuer_keys(&path, true).expect("load");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], vec![0xaa; 32]);

        std::fs::write(&path, "\n").expect("write empty");
        assert!(load_issuer_keys(&path, true).is_err());
        assert!(
            load_issuer_keys(&path, false)
                .expect("tolerated")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_cred_file_is_reported_with_the_path() {
        let config = CredentialsConfig {
            file: PathBuf::from("/nonexistent/cred.toml"),
            listen_addr: "0.0.0.0:3103".to_string(),
            store_path: PathBuf::from("state/credentials.json"),
            required_roles: vec!["read".to_string()],
        };
        let error = build(&config).expect_err("missing file must fail");
        assert!(error.contains("/nonexistent/cred.toml"), "{error}");
    }

    #[test]
    fn audience_placeholder_is_expanded_or_reported() {
        let dir = temp_dir("audience");
        let body = format!(
            "[verify]\naudience = \"${{FIELD_API_AUDIENCE}}\"\nallowed_issuers = [\"wist-cred\"]\nroles = [\"read\"]\n{INIT_AND_PUBLISH}"
        );
        // 环境里没有这个变量时：必须报“解不开”，而不是拿占位符当 audience 继续跑
        // （那种情况 cred 侧只会得到 400 audience_mismatch，错在对端、极难查）。
        let error = build_from(&dir, &body).expect_err("unresolved audience must fail");
        assert!(error.contains("unresolved environment variable"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 自注册：两种 cred.toml 形态 ──

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        // 计数器不能省：macOS 的 `SystemTime` 只到**微秒**，同一瞬间起的两个测试会撞同一纳秒值
        // → 共用目录 → 一个测试的材料被另一个覆盖。
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wist-field-api-cred-{tag}-{}-{}-{seq}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    const VERIFY: &str = r#"
[verify]
audience = "wist-field-api"
allowed_issuers = ["wist-cred"]
roles = ["read"]
"#;

    const INIT_AND_PUBLISH: &str = r#"
[init]
setup_code = "crp_test_setup_code"
cred_url = "https://cred.internal:4444"

[publish]
endpoint = "https://field.internal:18802/api/v1/internal/credentials"
"#;

    fn build_from(dir: &std::path::Path, body: &str) -> Result<CredentialRuntime, String> {
        let file = dir.join("cred.toml");
        std::fs::write(&file, body).expect("write cred.toml");
        build(&CredentialsConfig {
            file,
            listen_addr: "127.0.0.1:3103".to_string(),
            store_path: dir.join("credentials.json"),
            required_roles: vec!["read".to_string()],
        })
    }

    /// 一套真的 mTLS 材料：CA 签的服务器证书 + 私钥 + 客户端信任锚。
    fn write_materials(dir: &std::path::Path) {
        use wist_pki::CertificateAuthority;
        wist_pki::tls::install_crypto_provider();

        let (authority, ca_pem, _key) = CertificateAuthority::generate("Stub CA").expect("ca");
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "field.internal".to_string());
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let issued = authority
            .issue_server_certificate(&csr, &["field.internal".to_string()], 3600)
            .expect("issue");
        std::fs::write(dir.join("server.crt"), &issued.certificate_pem).expect("cert");
        std::fs::write(dir.join("server.key"), key.serialize_pem()).expect("key");
        std::fs::write(dir.join("client-ca.pem"), &ca_pem).expect("ca");
    }

    #[test]
    fn init_only_builds_but_stays_uninitialized() {
        let dir = temp_dir("initonly");
        let runtime = build_from(&dir, &format!("{VERIFY}{INIT_AND_PUBLISH}")).expect("build");
        // 没材料：不谎称已就绪，也不该把进程拦在启动期。
        assert!(!runtime.is_initialized());
        assert!(runtime.tls.is_none(), "no materials → no mTLS yet");
    }

    #[test]
    fn init_with_materials_on_disk_is_ready_at_startup() {
        // 注册完之后重启（容器重启 / 滚动发布）走的就是这条：材料在 → 立即起 mTLS。
        let dir = temp_dir("initwithmaterials");
        write_materials(&dir);
        let runtime = build_from(&dir, &format!("{VERIFY}{INIT_AND_PUBLISH}")).expect("build");
        assert!(runtime.is_initialized());
        assert!(runtime.tls.is_some());
    }

    #[test]
    fn join_command_identity_still_builds() {
        // 旧部署（接入命令写过 [identity]，没配 [init]）不能被 P1 弄坏。
        let dir = temp_dir("join");
        write_materials(&dir);
        let runtime = build_from(
            &dir,
            &format!(
                "{VERIFY}\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
            ),
        )
        .expect("build");
        assert!(runtime.is_initialized());
        assert!(runtime.tls.is_some());
    }

    #[test]
    fn neither_identity_nor_init_is_a_config_error() {
        let dir = temp_dir("neither");
        let error = build_from(&dir, VERIFY).expect_err("must refuse");
        assert!(error.contains("neither [identity] nor [init]"), "{error}");
    }

    #[test]
    fn join_command_without_materials_is_still_a_startup_error() {
        // 只配 [identity] 但文件不在：以前就在启动期拒，别因为 P1 变成“默默等”。
        let dir = temp_dir("joinmissing");
        let error = build_from(
            &dir,
            &format!(
                "{VERIFY}\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
            ),
        )
        .expect_err("must refuse");
        assert!(error.contains("[init] is not configured"), "{error}");
    }

    #[test]
    fn a_publish_endpoint_without_a_host_is_a_startup_error() {
        // 栈没渲染 FIELD_API_ADVERTISE_HOST 时就是 `https://:18802/…`：
        // 这种地址签不出可用的证书，必须在启动期说出来，而不是等初始化页莫名其妙地失败。
        let dir = temp_dir("nohost");
        let error = build_from(
            &dir,
            &format!(
                "{VERIFY}\n[init]\nsetup_code = \"crp_test_setup_code\"\n\n[publish]\nendpoint = \"https://:18802/api/v1/internal/credentials\"\n"
            ),
        )
        .expect_err("must refuse");
        assert!(error.contains("no usable host"), "{error}");
    }

    // ── 开关能用变量给（栈不改文件就能切） ──

    /// 只把 `[init].insecure_tls` 的写法参数化（其余固定）：
    /// 放在 `[init]` 里写，不能“尾部追加”——那样会落到最后一个段里，被静默忽略。
    fn init_toml(insecure_tls: &str) -> String {
        format!(
            "{VERIFY}\n[init]\nsetup_code = \"crp_test_setup_code\"\ninsecure_tls = {insecure_tls}\n\n[publish]\nendpoint = \"https://field.internal:18802/api/v1/internal/credentials\"\n"
        )
    }

    #[test]
    fn a_bool_can_be_written_as_a_literal_or_as_a_string() {
        let dir = temp_dir("boolish");
        // 字面 bool
        let runtime = build_from(&dir, &init_toml("true")).expect("literal bool must parse");
        assert!(!runtime.is_initialized());

        // 引号里的字符串（栈用 `"${FIELD_API_CRED_INSECURE_TLS}"`）
        build_from(&dir, &init_toml("\"false\"")).expect("quoted string must parse");
    }

    #[test]
    fn an_unparseable_bool_is_a_startup_error() {
        let dir = temp_dir("boolish-bad");
        let error = build_from(&dir, &init_toml("\"maybe\"")).expect_err("must refuse");
        assert!(error.contains("insecure_tls"), "{error}");
    }

    #[test]
    fn signature_verification_is_deferred_until_self_registration() {
        // 公钥是**自注册时随 bundle 下发**的，所以“还没初始化 + 强制验签 + 公钥不在”
        // 必须是可启动的：否则进程起不来 → 永远打不开 `/__init` → 死锁。
        // 用字符串形式（`"true"`）顺带证明“变量开关”真的生效：若当成 false，就不会延迟。
        let dir = temp_dir("sigdefer");
        let runtime = build_from(
            &dir,
            &format!(
                "{VERIFY}require_signature = \"true\"\nissuer_public_key_file = \"issuer-signing.pub\"\n\n[init]\nsetup_code = \"crp_test_setup_code\"\n\n[publish]\nendpoint = \"https://field.internal:18802/api/v1/internal/credentials\"\n"
            ),
        )
        .expect("uninitialized service must still start (key arrives with the bundle)");
        assert!(!runtime.is_initialized());
        assert!(
            runtime.signature_deferred(),
            "验签应当处于“延后”状态（否则就是静默关掉了）"
        );
    }

    #[test]
    fn an_initialized_service_without_the_issuer_key_refuses_to_start() {
        // 已经接入（材料齐备）却缺公钥 = 配置错，不能默默不验签。
        let dir = temp_dir("signok");
        write_materials(&dir);
        let error = build_from(
            &dir,
            &format!(
                "{VERIFY}require_signature = true\nissuer_public_key_file = \"issuer-signing.pub\"\n\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
            ),
        )
        .expect_err("must refuse");
        assert!(error.contains("issuer-signing.pub"), "{error}");
    }

    #[test]
    #[cfg(unix)]
    fn an_unreadable_client_ca_is_a_startup_error_not_a_silent_wait() {
        // 证书/私钥都在、只有 client CA 读不了：若当成“未初始化”，
        // cred-peer 仍认为已初始化 → /__init 回 409、listener 又起不来，
        // 现场表现成“一切正常但推不进来”。所以这里必须启动期就报。
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("unreadable-ca");
        write_materials(&dir);
        let ca = dir.join("client-ca.pem");
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let body = format!(
            "{VERIFY}\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
        );
        let error = build_from(&dir, &body).expect_err("must refuse");
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).expect("restore");
        assert!(error.contains("unreadable"), "{error}");
    }

    #[test]
    fn materials_deleted_at_runtime_are_reported_not_hidden() {
        // 运行中把三件材料删了：`is_initialized()` 立刻变 false，但 listener 还拿着
        // 启动时加载的证书在跑。两个事实都要能看见（见 `/api/health` 的文案），
        // 否则“重新注册成功但新证书没生效”会是个静默不一致。
        let dir = temp_dir("vanished");
        write_materials(&dir);
        let runtime = build_from(
            &dir,
            &format!(
                "{VERIFY}\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
            ),
        )
        .expect("build");
        assert!(runtime.is_initialized());
        assert!(runtime.serving_loaded_tls());

        for name in ["server.crt", "server.key", "client-ca.pem"] {
            std::fs::remove_file(dir.join(name)).expect("remove");
        }
        assert!(!runtime.is_initialized(), "材料没了就不再算已初始化");
        assert!(
            runtime.serving_loaded_tls(),
            "但 listener 仍在用启动时那套证书 —— 这个事实不能被抹掉"
        );
    }

    #[test]
    fn an_initialized_service_with_the_issuer_key_does_not_defer() {
        let dir = temp_dir("signready");
        write_materials(&dir);
        std::fs::write(
            dir.join("issuer-signing.pub"),
            format!("{}\n", "aa".repeat(32)),
        )
        .expect("key");
        let runtime = build_from(
            &dir,
            &format!(
                "{VERIFY}require_signature = true\nissuer_public_key_file = \"issuer-signing.pub\"\n\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
            ),
        )
        .expect("build");
        assert!(runtime.is_initialized());
        assert!(!runtime.signature_deferred(), "就绪后不应该再降级");
    }

    #[test]
    fn require_signature_switched_on_by_a_string_really_applies() {
        // 已初始化 + 强制验签 + 缺公钥 → 启动期报（fail-closed），
        // 顺带证明 `"true"` 真的被当成开关解析了，而不是“看起来配了实际没开”。
        let dir = temp_dir("sigwire");
        write_materials(&dir);
        let error = build_from(
            &dir,
            &format!(
                "{VERIFY}require_signature = \"true\"\nissuer_public_key_file = \"issuer-signing.pub\"\n\n[identity]\ncert = \"server.crt\"\nkey = \"server.key\"\nclient_ca = \"client-ca.pem\"\n"
            ),
        )
        .expect_err("must refuse");
        assert!(error.contains("issuer-signing.pub"), "{error}");
    }

    #[test]
    fn an_unresolved_publish_endpoint_is_a_startup_error() {
        // 栈渲染的地址是 `https://${FIELD_API_ADVERTISE_HOST}:${CREDENTIALS_HOST_PORT}/…`。
        // 变量没渲染时必须**当场**报：占位符能冒充一个主机名，证书真能签出来，
        // 错要等到 cred 拨号才暴露（而且错在对方）。
        let dir = temp_dir("endpointvar");
        let error = build_from(
            &dir,
            &format!(
                "{VERIFY}\n[init]\nsetup_code = \"crp_test_setup_code\"\n\n[publish]\nendpoint = \"https://${{FIELD_API_ADVERTISE_HOST_UNSET}}:18802/api/v1/internal/credentials\"\n"
            ),
        )
        .expect_err("must refuse");
        assert!(error.contains("unresolved environment variable"), "{error}");
    }
}
