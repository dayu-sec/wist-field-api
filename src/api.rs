//! HTTP 面：浏览器 → BFF。
//!
//! 两条纪律：
//! 1. **浏览器不持凭据**：到证据服务的身份（租户 / scope / 敏感度）只来自配置；
//! 2. **不做二次判断**：证据服务回什么就回什么（404 保持 404），BFF 只负责转发与聚合。

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::config::{AuthMode, Config};
use crate::metrics;
use crate::upstream::{EvidenceClient, UpstreamResponse};

/// 数据面的 wparse 通过哪个环境变量拿到本栈 VM 的写入地址。
///
/// 与网关栈（写控制面那份 VM）用的是同一个变量名 —— 同一个业务分组镜像到两份存储时，
/// 只改环境变量的值，不改配置。写在这里是因为它**是协议事实、不是部署事实**：
/// 页面不该再手写一遍，否则名字一改就两边对不上。
const METRICS_ENDPOINT_ENV: &str = "CONSOLE_VM_ENDPOINT";
/// VM 的 JSON line 导入路径（`agent_metrics` 分组用的就是这条）。
const METRICS_IMPORT_PATH: &str = "/api/v1/import";

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub evidence: Arc<EvidenceClient>,
    pub http: reqwest::Client,
    /// `auth.mode = "cred"` 时存在；`ingress` 时 `None`。
    pub credentials: Option<Arc<crate::credentials::CredentialRuntime>>,
}

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/health", get(health))
        .route("/api/evidence", get(list_evidence))
        // 能力自述：页面据此选「打开正文」的通路（签名 URL / BFF 代理读）。
        // 静态段优先于下面的 `/api/evidence/{cmd_id}`，不会把 id 吃掉。
        .route("/api/evidence/capabilities", get(evidence_capabilities))
        // 接口清单：证据读接口的对外面就是本服务（浏览器到不了证据服务的 `/internal/*`），
        // 所以由 BFF 出 spec，页面拿它渲染「接口可用性」页，不维护第二份。
        .route("/api/evidence/openapi.json", get(evidence_openapi))
        .route("/api/integration", get(integration))
        // 运行指标：读计算区自己那份 VictoriaMetrics（数据面镜像写进来的）。
        // 概览 + 单台 agent 的趋势；两个都只读，不做跨栈聚合。
        .route("/api/metrics", get(metrics::overview))
        .route(
            "/api/metrics/agents/{agent_id}/history",
            get(metrics::agent_history),
        )
        // 资产拓扑的数据面走 BFF：atlas-web 在 `/atlas/` 里发起的 `/atlas/api/...` 被反代到这里，
        // 所以令牌校验与其它 `/api/*` 是同一道门（不再从 nginx 直连 atlas）。
        // 只放 GET：atlas 的写端点是同一监听的 `/internal/atlas`（POST），浏览器不该碰得到。
        .route("/api/atlas/{*rest}", get(proxy_atlas))
        .route(
            "/api/evidence/{cmd_id}",
            get(get_evidence).post(presign_evidence),
        )
        // 代理读正文：预签名不可用的部署（证据服务 objects.kind = file）走这条。
        .route("/api/evidence/{cmd_id}/content", get(get_evidence_content))
        .with_state(state.clone());

    // 登录端点：把一条访问令牌换成「你是谁 + 给了什么角色」。
    // 契约由 `wist-cred-peer` 统一（0.5 起），宿主只决定挂在哪、要什么角色；
    // 挂在 503 门**之前**：没材料时连令牌都没得验，应当与业务面一起拒。
    if let Some(credentials) = state.credentials.as_ref() {
        router = router.nest(
            "/api",
            wist_cred_peer::login_router(credentials.peer(), credentials.required_roles().to_vec()),
        );
    }

    // 未初始化时只放行 `/__init`（和 `/healthz`）：业务面一律 503 ——
    // 否则会出现“页面能打开但永远 401”的半可用现场。
    router = router.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        require_initialized,
    ));

    // 自注册：未初始化时 `GET/POST /__init`；初始化后它自己回 409。
    if let Some(credentials) = state.credentials.as_ref() {
        router = router.merge(wist_cred_peer::init_router(credentials.peer()));
    }
    router
}

/// 未初始化（没有 cred 材料）时，`/api/*` 一律 503。
async fn require_initialized(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let uninitialized = state
        .credentials
        .as_ref()
        .is_some_and(|credentials| !credentials.is_initialized());
    if uninitialized && request.uri().path().starts_with("/api/") {
        // 这一条是现场**唯一**能看到的状态描述（`/api/health` 自己也在这道门后面），
        // 所以要把“运行中删了材料”这件事直接写在这里，而不是只写进日志。
        let deleted_at_runtime = state
            .credentials
            .as_ref()
            .is_some_and(|credentials| credentials.serving_loaded_tls());
        let message = if deleted_at_runtime {
            "identity materials were removed while this service was running: the push listener \
             still holds the certificate loaded at startup — re-register at /__init, then \
             RESTART this service so the new certificate is actually served"
        } else {
            "this service has no cred materials yet: open /__init to register it"
        };
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": {
                    "code": "peer_not_initialized",
                    "message": message,
                }
            })),
        )
            .into_response();
    }
    next.run(request).await
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// 聚合各数据源的就绪度。`not_configured` 不是错误 —— 是「这个域还没接」。
///
/// `interfaces` 是给「接口可用性」页用的：每个条目要么是一次真请求的结果，
/// 要么是「没配地址」。`covers` 写清楚这一次请求到底验到了哪一层——
/// 运维看「绿」时需要知道它绿的是什么。
#[derive(serde::Serialize)]
struct Health {
    status: &'static str,
    sources: serde_json::Value,
    interfaces: serde_json::Value,
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }

    let write_url = state.config.integration.sink_health_url.clone();
    let atlas_url = state
        .config
        .atlas
        .as_ref()
        .map(|atlas| format!("{}/healthz", atlas.base_url.trim_end_matches('/')));
    let metrics_url = state
        .config
        .metrics
        .as_ref()
        .map(|metrics| format!("{}/health", metrics.base_url.trim_end_matches('/')));

    // 并发探活：一个上游挂掉不该把另外两个的延迟一起拖长。
    let (read_iface, write_iface, atlas_iface, metrics_iface, credentials_iface) = tokio::join!(
        probe_evidence_read(&state),
        probe_opt(
            &state.http,
            "evidence_write",
            "证据写端点",
            "BFF → 证据写监听：端口就绪 + 服务自报的写探针（每 5 分钟一笔真写入）。\n数据面到该地址的网络可达性只能由数据面自己验证。",
            write_url,
            "未配置 integration.sink_health_url（BFF 视角的探活地址）",
        ),
        probe_opt(
            &state.http,
            "atlas",
            "资产拓扑 API",
            "BFF → 资产拓扑：`/healthz` 进程就绪 + 服务自报的写探针\n（转换 → 落库 → 物化 一整条；与 evidence 的 `probe` 块同一形状）。",
            atlas_url,
            "未配置 atlas.base_url",
        ),
        probe_opt(
            &state.http,
            "metrics",
            "运行指标存储",
            "BFF → VictoriaMetrics：`/health` 可查询。只证明存储活着，\n不代表数据面正在上报（那是数据面自己的事）。",
            metrics_url,
            "未配置 metrics.base_url",
        ),
        async { credentials_interface(&state) },
    );

    // `sources` 由同一次探活派生，不再重复发请求。
    let evidence = source_from(&read_iface);
    let atlas = source_from(&atlas_iface);
    let metrics = source_from(&metrics_iface);
    let interfaces = vec![
        read_iface,
        write_iface,
        atlas_iface,
        metrics_iface,
        credentials_iface,
    ];

    Json(Health {
        status: "ok",
        interfaces: json!(interfaces),
        sources: json!({
            "evidence": evidence,
            "atlas": atlas,
            "metrics": metrics,
            "devices": {
                "status": "not_configured",
                "detail": "containment_capabilities 尚未上报",
            },
        }),
    })
    .into_response()
}

/// 展示给运维的「数据面接入」：写端点 + 可直接 copy 的 wparse 配置。
///
/// **不回传站点 token**，只回占位符。
async fn integration(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let sink_base = state
        .config
        .integration
        .sink_url
        .clone()
        .unwrap_or_else(|| "http://<证据服务内网地址>:18800".to_string());
    let sink_base = sink_base.trim_end_matches('/').to_string();
    let write_url = format!("{sink_base}/internal/evidence");

    // 环境变量只给**数据面能看到的**地址；atlas 没配写地址就不出现在 env 里。
    let atlas_base = state.config.atlas.as_ref().and_then(|atlas| {
        atlas
            .sink_url
            .as_ref()
            .map(|sink_url| sink_url.trim_end_matches('/').to_string())
    });
    let mut env = serde_json::Map::new();
    env.insert("EVIDENCE_SINK_URL".to_string(), json!(sink_base));
    if let Some(atlas_base) = atlas_base.as_ref() {
        env.insert("ATLAS_SINK_URL".to_string(), json!(atlas_base));
    }

    // 运行指标：**数据面视角**的写入端点 + 协议事实（变量名 / 导入路径）。
    //
    // 这三样必须由配置 + 一处常量坐实：它们出现在页面的可复制样板里，
    // 一旦有人手写一遍，地址或变量名就会与真实部署漂开 ——
    // 而漂开的后果是「接完了但没数据」，最难查。
    let metrics = state.config.metrics.as_ref().and_then(|metrics| {
        let write_url = metrics
            .write_url
            .as_ref()?
            .trim_end_matches('/')
            .to_string();
        env.insert(METRICS_ENDPOINT_ENV.to_string(), json!(write_url));
        Some(json!({
            "write_url": write_url,
            "import_path": METRICS_IMPORT_PATH,
            "env": METRICS_ENDPOINT_ENV,
            // BFF 视角的查询入口（栈内）；页面只用它做探活归属说明。
            "base_url": metrics.base_url,
        }))
    });

    let atlas = atlas_base.map(|base| {
        json!({
            "write_url": format!("{base}/internal/atlas"),
            "auth": "none",
            // `cust_id` 是 atlas 的租户 UUID（不是客户号）：一个 wparse 可以写多个租户。
            "customer": "<atlas 租户 UUID>",
            // 资产拓扑写端点：只有两个字段 —— 证据服务的 `cmd_id` 是它自己的幂等键，
            // atlas 写的是状态快照，幂等键在快照的 `snap_id` 里。
            "record": {
                "cust_id": "<atlas 租户 UUID>",
                "content": { "schema": "v1", "biz": "agent-discovery", "body": "<DSNAP 快照 JSON 字符串>" },
            },
        })
    });

    Json(json!({
        "evidence": {
            "write_url": write_url,
            "auth": "none",
            // `tenant` 就是客户 id：租户与客户已经合并成一个维度。
            "customer": state.config.evidence.tenant,
            "allowed_kinds": state.config.integration.allowed_kinds,
            "record": {
                "cust_id": state.config.evidence.tenant,
                "cmd_id": "cmd-20261105-001",
                "content": { "summary": { "overall": "warn" }, "findings": [] },
            },
        },
        // 资产拓扑写端点：只有两个字段（证据服务的 `cmd_id` 是它自己的幂等键）。
        "atlas": atlas,
        // 运行指标写端点：同样是**数据面视角**。
        // 没配 `[metrics] write_url` 时为 null —— 不编造占位地址。
        "metrics": metrics,
        // 接入样板里的 sink 分组由页面现场拼（复用现成的 `http_sink`），
        // BFF 只回数据面要用的环境变量 —— 不再下发 `[[connectors]]` 定义。
        "warp_parse": {
            "env": env,
        },
    }))
    .into_response()
}

/// `GET /api/evidence/capabilities`：证据服务的部署自述（当前只有对象后端）。
///
/// 页面据 `presign_supported` 决定「打开正文」走哪条路：
/// - `objects.kind = s3`：一次 60s 单对象签名，浏览器直连对象存储；
/// - `objects.kind = file`：没有签名 URL，走 BFF 代理读（`/api/evidence/{id}/content`）。
///
/// 探测失败、或老证据服务的 `/healthz` 不报 `objects` 时回 `objects_kind: null`
/// 且 `presign_supported: true`：页面退回到「先试签名、501 再回落」的老行为 ——
/// 能力探测失败不应该把正文读不了当结果。
async fn evidence_capabilities(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let response = match state.evidence.health().await {
        Ok(response) => response,
        Err(err) => return upstream_failed(err),
    };
    let objects_kind = evidence_objects_kind(&response.body);
    let presign_supported = objects_kind.as_deref() != Some("file");
    Json(json!({
        "objects_kind": objects_kind,
        "presign_supported": presign_supported,
    }))
    .into_response()
}

/// `GET /api/evidence/openapi.json`：证据读接口的 OpenAPI 自述。
///
/// 与 `/api/health` 一样只要操作员身份：spec 本身不含数据，但它是浏览器能看到的
/// 接口清单，没必要在未登录时暴露。
async fn evidence_openapi(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    Json(crate::openapi::evidence()).into_response()
}

/// 从证据服务 `/healthz` 正文里取 `objects.kind`；形状不认识就当不知道（`None`）。
fn evidence_objects_kind(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("objects")?
        .get("kind")?
        .as_str()
        .map(str::to_string)
}

async fn list_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let query = query
        .map(|raw| strip_tenant(&raw))
        .filter(|raw| !raw.is_empty());
    match state.evidence.list(query.as_deref()).await {
        Ok(response) => passthrough(response),
        Err(err) => upstream_failed(err),
    }
}

/// `GET /api/evidence/{cmd_id}`：读一条证据的索引行。
///
/// 路径里的 key 可以是**调查命令 id**（`cmd_id`，发起调查的人手里只有这个），
/// 也可以是列表行里的证据 id（`art_…`）—— 证据服务按先后顺序自己找。
/// BFF 只做路径安全校验与透传，不替调用方判哪个是哪种 id。
async fn get_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(key) = valid_evidence_key(&key) else {
        return not_found();
    };
    match state.evidence.get(key).await {
        Ok(response) => passthrough(response),
        Err(err) => upstream_failed(err),
    }
}

/// `POST /api/evidence/{cmd_id}:presign`（key 也接受证据 id）。
///
/// 与证据服务同一条路由技巧：`{cmd_id}` 会把 `art_x:presign` 整段吃下来。
/// `GET /api/evidence/{cmd_id}/content`：原文代理读。
///
/// 本地文件存储（`objects.kind = file`）不签发预签名 URL，页面就用这条拿正文：
/// BFF 带自己的身份去证据服务取原文，浏览器始终不碰任何凭据。
async fn get_evidence_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(key) = valid_evidence_key(&key) else {
        return not_found();
    };
    match state.evidence.content(key).await {
        Ok(response) => passthrough_uncached(response),
        Err(err) => upstream_failed(err),
    }
}

/// 资产拓扑读接口的代理：`GET /api/atlas/hosts` → `{atlas.base_url}/hosts`。
///
/// 为什么放在 BFF 而不是让 nginx 直连 atlas：`/atlas/` 里的前端是 iframe，它拿不到
/// 我们塞在 JS 里的令牌；把它收到 BFF 后面，鉴权就只有一条路（`require_operator`）。
async fn proxy_atlas(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rest): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(atlas) = state.config.atlas.as_ref() else {
        return error_response(
            StatusCode::NOT_FOUND,
            "atlas_not_configured",
            "this service has no atlas.base_url configured",
        );
    };
    // 写端点与路径穿越都不放行：这里只代理 atlas 的公开读接口。
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() || rest.contains("..") || rest.contains("//") || rest.starts_with("internal")
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "atlas_path_invalid",
            "invalid atlas path",
        );
    }

    // atlas 的读接口都在 `/api/*` 下（写端点是 `/internal/atlas`）。
    // 前端看到的是 `/atlas/api/hosts`，到这里剩下 `hosts`，补回 `/api` 才是 atlas 的路径。
    let mut url = format!("{}/api/{rest}", atlas.base_url.trim_end_matches('/'));
    if let Some(query) = query.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(query);
    }

    // atlas 从 0.3.4 起读接口要令牌；BFF 是唯一该拿到它的调用方。
    let mut request = state.http.get(&url);
    if let Some(token) = atlas.auth_token.as_deref() {
        request = request.bearer_auth(token);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => return upstream_failed(err.to_string()),
    };
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(err) => return upstream_failed(err.to_string()),
    };
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/json")),
    );
    // 拓扑数据是“某一刻的状态”，不进浏览器缓存。
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn presign_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> Response {
    if let Err(err) = require_operator(&state, &headers) {
        return err.into_response();
    }
    let Some(key) = raw.strip_suffix(":presign") else {
        return not_found();
    };
    let Some(key) = valid_evidence_key(key) else {
        return not_found();
    };
    match state.evidence.presign(key).await {
        Ok(response) => passthrough(response),
        Err(err) => upstream_failed(err),
    }
}

/// 调用方身份：谁在看这个界面（审计日志用）。
///
/// - `cred`（默认）：`Authorization: Bearer wcr_…` → 摘要表比对 → 角色判权；
/// - `ingress`：入口（VPN / 堡垒机 / 反代）已认证，把操作员写在头里。
///
/// 没有「不校验」这一档：任何一个分支都必须能说出「这是谁」。
fn require_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, OperatorError> {
    match state.config.auth.mode {
        AuthMode::Ingress => {
            let name = &state.config.auth.operator_header;
            let value = headers
                .get(name.as_str())
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty());
            match value {
                Some(operator) => Ok(Some(operator.to_string())),
                None => Err(OperatorError::MissingHeader(name.clone())),
            }
        }
        AuthMode::Cred => {
            let Some(token) = bearer_token(headers) else {
                return Err(OperatorError::MissingCredential);
            };
            // 配置层保证 `cred` 模式一定有 credentials；这里只是不让 None 静默放行。
            let Some(verifier) = state.credentials.as_ref() else {
                log::error!("auth.mode = cred but no credential runtime is wired");
                return Err(OperatorError::InvalidCredential);
            };
            match verifier.verify(token) {
                Ok(caller) => Ok(Some(caller.subject)),
                Err(crate::credentials::VerifyError::RoleRequired) => {
                    Err(OperatorError::RoleRequired)
                }
                Err(crate::credentials::VerifyError::StoreUnavailable) => {
                    Err(OperatorError::StoreUnavailable)
                }
                // 不对外区分「不认识 / 过期 / 撤销 / audience 不符」。
                Err(crate::credentials::VerifyError::Invalid) => {
                    Err(OperatorError::InvalidCredential)
                }
            }
        }
    }
}

/// 同一道门，给 api 以外的模块（运行指标）用：拒绝时直接给出响应。
pub(crate) fn authorize(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    require_operator(state, headers)
        .err()
        .map(|err| err.into_response())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// 小结构而不是 `Response`：后者会把 `Result` 撑到上百字节（clippy::result_large_err）。
enum OperatorError {
    /// `ingress` 模式：入口没注入操作者头。
    MissingHeader(String),
    /// `cred` 模式：没带 token。
    MissingCredential,
    /// `cred` 模式：token 不认识 / 过期 / 撤销。
    InvalidCredential,
    /// `cred` 模式：token 有效，但角色不够（403，不是 401）。
    RoleRequired,
    /// 摘要表读不了：服务端故障，**不是**「你的令牌不对」（503）。
    StoreUnavailable,
}

impl OperatorError {
    fn into_response(self) -> Response {
        match self {
            Self::MissingHeader(header) => error_response(
                StatusCode::UNAUTHORIZED,
                "field_operator_missing",
                format!("missing ingress operator header {header}"),
            ),
            Self::MissingCredential => error_response(
                StatusCode::UNAUTHORIZED,
                "field_credential_missing",
                "missing access token: send `Authorization: Bearer <token>`",
            ),
            Self::InvalidCredential => error_response(
                StatusCode::UNAUTHORIZED,
                "field_credential_invalid",
                "access token is not valid for this service",
            ),
            Self::RoleRequired => error_response(
                StatusCode::FORBIDDEN,
                "field_role_required",
                "access token is valid but does not grant access",
            ),
            Self::StoreUnavailable => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "field_credential_store_unavailable",
                "credential store is unavailable; this is a server-side problem, not your token",
            ),
        }
    }
}

/// 路径里的证据 key（证据 id 或调查命令 id）只做**路径安全**校验。
///
/// 不在这里判断它是 `art_…` 还是 `cmd_…`：那是证据服务的定位规则，
/// BFF 只负责不让 `/`、`..` 之类的段穿过去。
fn valid_evidence_key(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains("..") {
        return None;
    }
    Some(trimmed)
}

/// 租户永远来自配置；浏览器带的 `tenant` 参数一律丢掉。
fn strip_tenant(query: &str) -> String {
    query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.starts_with("tenant="))
        .collect::<Vec<_>>()
        .join("&")
}

fn passthrough(response: UpstreamResponse) -> Response {
    let mut builder = Response::new(axum::body::Body::from(response.body));
    *builder.status_mut() = response.status;
    builder.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    builder
}

/// 正文透传：多带两条头。
/// - `no-store`：证据正文不能被浏览器 / 中间代理缓存（它有过期与保密要求）；
/// - `nosniff`：正文是 JSON 文件，不能让浏览器猜成 HTML。
fn passthrough_uncached(response: UpstreamResponse) -> Response {
    let mut builder = passthrough(response);
    builder
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    builder.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    builder
}

fn upstream_failed(message: String) -> Response {
    error_response(StatusCode::BAD_GATEWAY, "field_upstream_failed", message)
}

/// 没配地址的接口直接标 `not_configured`；这是「还没接」，不是故障。
async fn probe_opt(
    http: &reqwest::Client,
    id: &str,
    label: &str,
    covers: &str,
    target: Option<String>,
    missing_detail: &str,
) -> serde_json::Value {
    match target {
        Some(url) => probe(http, id, label, covers, &url).await,
        None => entry(
            id,
            label,
            covers,
            None,
            "not_configured",
            Some(missing_detail.to_string()),
            None,
        ),
    }
}

/// 单接口探活：状态 + 延迟 + 检查时间。错误信息截断，避免把整段 reqwest 报错塞进页面。
async fn probe(
    http: &reqwest::Client,
    id: &str,
    label: &str,
    covers: &str,
    url: &str,
) -> serde_json::Value {
    let started = std::time::Instant::now();
    let result = http
        .get(url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(response) if response.status().is_success() => {
            // 证据服务的 `/healthz` 会带 `probe` 块（每 5 分钟一条真实写入的结果），
            // 有就翻成一句人话，没有就留空。
            let detail = write_probe_detail(response).await;
            entry(id, label, covers, Some(url), "ok", detail, Some(latency_ms))
        }
        Ok(response) => entry(
            id,
            label,
            covers,
            Some(url),
            "unavailable",
            Some(format!("HTTP {}", response.status().as_u16())),
            Some(latency_ms),
        ),
        Err(err) => entry(
            id,
            label,
            covers,
            Some(url),
            "unavailable",
            Some(truncate(&err.to_string())),
            Some(latency_ms),
        ),
    }
}

/// 访问凭据的状态：**不发请求**，看的就是本进程手里的两个事实 ——
/// 收数 listener 还在不在、摘要表里登记了几条。
///
/// 这条必须存在：peer 在 cred 侧「注册了但没有 endpoint」时，现象只是「令牌全 401」，
/// 页面上一眼看不出来；而 `registered = 0` 直接把「还没人推过来」摆到脸上。
fn credentials_interface(state: &AppState) -> serde_json::Value {
    let Some(credentials) = state.credentials.as_ref() else {
        return entry(
            "credentials",
            "访问凭据（wist-cred）",
            "本服务是 `wist-cred` 的验证方：cred 通过 mTLS 推摘要，浏览器用 `Bearer wcr_…` 访问。\n\
             当前 `auth.mode = ingress`，凭据不参与认证。",
            None,
            "not_configured",
            Some("auth.mode = ingress：认证交给入口".to_string()),
            None,
        );
    };

    let registered = credentials.registered();
    let rejected = credentials.rejected_on_load();
    let alive = credentials.listener_alive();
    let listen = credentials.listen();

    let (status, detail) = if !credentials.is_initialized() {
        if credentials.serving_loaded_tls() {
            // 运行中删了材料：listener 还在用启动时加载的那套证书。
            // 不说清楚的话，注册完会出现“看着成功了、新证书其实没被加载”的静默不一致。
            (
                "unavailable",
                "身份材料在运行期被删除：收数监听仍在用启动时加载的旧证书。\
                 重新注册（/__init）之后必须**重启**本服务，新证书才会生效"
                    .to_string(),
            )
        } else {
            (
                "unavailable",
                "尚未初始化：浏览器打开 /__init，填 setup code + 接入券完成注册（业务面现在全部 503）"
                    .to_string(),
            )
        }
    } else if !alive {
        (
            "unavailable",
            format!(
                "收数监听 {listen} 不在运行：新凭据推不进来（已登记的 {registered} 条仍然有效）"
            ),
        )
    } else if registered == 0 {
        (
            "unavailable",
            format!(
                "收数监听 {listen} 在线，但一条凭据都没登记：先看 cred 页面上这个系统是不是 \
                 no_endpoint（没登记地址就永远不会推过来；地址在 cred 页面 / 部署栈里登记，\
                 不是接入命令的参数），再看 cred 到 {listen} 的可达性"
            ),
        )
    } else {
        (
            "ok",
            format!("已登记 {registered} 条凭据；收数监听 {listen} 在线"),
        )
    };
    // “正在降级运行”不能只写在日志里（运维不看容器日志就会以为一切正常）。
    let detail = if credentials.signature_deferred() {
        format!(
            "{detail}；⚠ 授权记录验签**未启用**：启动时公钥还没下发（自注册之前无法存在），\
             完成注册后重启本服务即开始强制验签"
        )
    } else {
        detail
    };

    let mut detail = detail;
    if rejected > 0 {
        detail.push_str(&format!(
            "。⚠ 启动时有 {rejected} 条记录因签名不合格被丢弃（磁盘被改过 / 签名密钥换过）"
        ));
    }

    entry(
        "credentials",
        "访问凭据（wist-cred）",
        "本服务是 `wist-cred` 的验证方：cred 通过 mTLS 推摘要（只存 sha256），\
         浏览器用 `Authorization: Bearer wcr_…` 访问。这一条挂掉 = 没人能登录。",
        None,
        status,
        Some(detail),
        None,
    )
}

/// 读端点用**真读**探活（`limit=1`）：鉴权、租户/敏感度闸、PG 索引都会走到，
/// 比只戳 `/healthz` 有意义——读端点挂了，证据页就是空的。
async fn probe_evidence_read(state: &AppState) -> serde_json::Value {
    const COVERS: &str = "BFF → 证据服务：带服务身份真读一次 `GET /internal/evidence?limit=1`，\
覆盖鉴权、租户与敏感度闸、PG 索引。这一条挂了，证据页就是空的。";
    let url = format!(
        "{}/internal/evidence?limit=1",
        state.config.evidence.base_url.trim_end_matches('/')
    );
    let started = std::time::Instant::now();
    let result = state.evidence.list(Some("limit=1")).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(response) if response.status.is_success() => entry(
            "evidence_read",
            "证据读端点",
            COVERS,
            Some(&url),
            "ok",
            None,
            Some(latency_ms),
        ),
        Ok(response) => entry(
            "evidence_read",
            "证据读端点",
            COVERS,
            Some(&url),
            "unavailable",
            Some(format!("HTTP {}", response.status.as_u16())),
            Some(latency_ms),
        ),
        Err(err) => entry(
            "evidence_read",
            "证据读端点",
            COVERS,
            Some(&url),
            "unavailable",
            Some(truncate(&err)),
            Some(latency_ms),
        ),
    }
}

/// 探活结果统一形状：没配地址时不计延迟/时间（那不是一次检查）。
/// `{"probe":{...}}` → 「写探针 12 秒前成功（3 ms）」。
/// 不是证据服务的健康响应 / 没开探针时返回 `None`。
async fn write_probe_detail(response: reqwest::Response) -> Option<String> {
    let body: serde_json::Value = response.json().await.ok()?;
    let probe = body.get("probe")?;
    let last_ok = probe.get("last_ok").and_then(serde_json::Value::as_bool);
    let failures = probe
        .get("consecutive_failures")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    match last_ok {
        Some(false) => return Some(format!("写探针失败（连续 {failures} 次）")),
        None => return Some("写探针还没跑过".to_string()),
        Some(true) => {}
    }
    let checked_at_ms = probe
        .get("last_at_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let latency_ms = probe
        .get("last_latency_ms")
        .and_then(serde_json::Value::as_u64);
    let age_secs = (now_ms().saturating_sub(checked_at_ms)) / 1000;
    match latency_ms {
        Some(latency_ms) => Some(format!("写探针 {age_secs} 秒前成功（{latency_ms} ms）")),
        None => Some(format!("写探针 {age_secs} 秒前成功")),
    }
}

fn entry(
    id: &str,
    label: &str,
    covers: &str,
    url: Option<&str>,
    status: &str,
    detail: Option<String>,
    latency_ms: Option<u64>,
) -> serde_json::Value {
    let mut value = json!({
        "id": id,
        "label": label,
        "covers": covers,
        "status": status,
    });
    if let Some(url) = url {
        value["url"] = json!(url);
    }
    if let Some(detail) = detail {
        value["detail"] = json!(detail);
    }
    if let Some(latency_ms) = latency_ms {
        value["latency_ms"] = json!(latency_ms);
        value["checked_at_ms"] = json!(now_ms());
    }
    value
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn truncate(text: &str) -> String {
    let mut out: String = text.chars().take(180).collect();
    if out.len() < text.len() {
        out.push('…');
    }
    out
}

/// 接口探活结果 → 数据源就绪度（只取状态与详情，丢掉延迟这类接口级字段）。
fn source_from(probe: &serde_json::Value) -> serde_json::Value {
    match probe.get("detail") {
        Some(detail) => json!({ "status": probe["status"], "detail": detail }),
        None => json!({ "status": probe["status"] }),
    }
}

fn not_found() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "evidence_not_found",
        "artifact not found",
    )
}

pub(crate) fn error_response(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}
