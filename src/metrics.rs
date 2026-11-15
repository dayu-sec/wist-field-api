//! 运行指标：读计算区**自己那份** VictoriaMetrics。
//!
//! 数据面（wparse）把 agent 采集指标镜像进来（网关栈的 `CONSOLE_VM_ENDPOINT`），
//! 网关栈那份 VM 只服务控制面观测页 —— 两份存储互不聚合（谁写谁查）。
//! 所以这里**看不到**引擎 / 管道统计（`wparse_*` 只写网关栈），这是刻意的边界。
//!
//! 两条纪律：
//! 1. 指标名只从 `wist-metrics` 的常量表取：读侧手写名字曾经把整页刷成静默空白；
//! 2. 单位在 BFF 换算成页面口径（百分比 / 毫秒 / 字节），前端只画图不做算术。
//!
//! 页面的四层表达（业务 / 服务 / 中间件 / 计算资源）在这里只做前两层：
//! 业务层来自 `field-api.toml` 的主机归属（见 [`BusinessRow`]），服务层与中间件层
//! 由前端按 `app` label 与指标名前缀分组（无需额外查询）。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wist_metrics::names::{agent as agent_metric, label, ratio_to_percent, seconds_to_millis};
use wist_metrics::spec::METRIC_SPECS;

use crate::api::{
    AppState, authorize_principal, error_response, now_ms, tenant_error, tenant_from_query,
};
use crate::config::BusinessUnit;

/// 「有没有在跳」的观察窗口（秒）：这段时间里一个样本都没有 = 采集静默。
const SAMPLE_WINDOW_SECONDS: i64 = 300;
/// 单次查询超时。VM 就在栈内网，慢到这个程度说明它自己有问题。
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);

/// 窗口的上界：看板允许「近 N 分钟」这种自定义窗口，但不接受任意值 ——
/// `[7d]` 这种窗口会把响应撑到几 MB。
const MIN_WINDOW_SECONDS: i64 = 300;
const MAX_WINDOW_SECONDS: i64 = 86_400;

/// 选择类 label（由网关下发、贴在全部序列上）。只有这些算「这台 agent 的身份」；
/// `target_kind` / `outcome` 之类是**某条指标自己的**属性，混进身份会让同一台机器裂成多行。
/// 名单与数据面 `adm.oml` 的选择类 label 一致。
const SELECTION_LABELS: &[&str] = &[
    "env", "cluster", "app", "role", "shard", "tier", "region", "zone",
];

#[derive(Debug, Default, Clone, Serialize)]
pub struct HostMetrics {
    pub hostname: Option<String>,
    pub ip_addresses: Vec<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub kernel: Option<String>,
    pub load_1m: Option<f64>,
    pub load_5m: Option<f64>,
    pub load_15m: Option<f64>,
    pub memory_total_bytes: Option<f64>,
    pub memory_available_bytes: Option<f64>,
    /// 已换算成百分比（VM 里存的是 0~1 的 ratio）。
    pub memory_usage_percent: Option<f64>,
    /// 系统盘（`disk_role=system`）使用率，百分比。
    pub disk_usage_percent: Option<f64>,
    pub disk_total_bytes: Option<f64>,
    pub disk_available_bytes: Option<f64>,
    /// 最紧张的挂载点（可能不是系统盘根分区），百分比。
    pub filesystem_usage_percent: Option<f64>,
    pub filesystem_mount: Option<String>,
    pub uptime_seconds: Option<f64>,
    /// 采集到的进程数（`process_pid` 的序列数）。
    pub processes: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub struct AgentRow {
    pub agent_id: String,
    /// 选择类 label（`env` / `cluster` / …），按名字排序。
    pub labels: BTreeMap<String, String>,
    /// 这台 agent 在存储里的序列总数（含 `system_*` / `process_*`）。
    pub series: u64,
    /// 观察窗口内 `agent_cpu_ratio` 的样本数：`0` = 采集静默。
    pub samples: u64,
    pub cpu_percent: Option<f64>,
    pub cpu_cores: Option<f64>,
    pub memory_bytes: Option<f64>,
    pub admin_latency_ms: Option<f64>,
    /// 采集记账：窗口内每批按 `target_kind` × `outcome` 报的目标数（按 outcome 汇总）。
    pub collect_targets: Option<f64>,
    pub collect_dropped: Option<f64>,
    pub uplink_failed_total: Option<f64>,
    pub discovery_policy_version: Option<f64>,
    /// 主机侧（`system_*` / `process_*`）：**宿主**的资源，不是 agent 进程自己的。
    /// 老 agentd 只报自观测时这里会是空值，页面显示「—」。
    pub host: HostMetrics,
}

#[derive(Debug, Serialize)]
pub struct CatalogEntry {
    pub name: String,
    /// 名字前缀（`agent` / `system` / `process` / …），页面按它分组。
    pub group: String,
    pub series: u64,
}

/// 业务层：把「主机集合」聚成一个命名的逻辑单元（用于投入产出比）。
///
/// 归属关系来自 `field-api.toml` 的 `[[business.units]]`，**不在指标 label 里**：
/// 一台主机算谁的，是部署方的记账口径，不是 agentd 该知道的事。
///
/// 聚合口径按物理意义分开：
/// - **求和**：内存占用、进程数、采集目标数、核数（可以跨机累加）；
/// - **取最大值**：负载、磁盘 / 挂载点使用率（本来就是单机口径，相加没有意义）。
#[derive(Debug, Clone, Default, Serialize)]
pub struct BusinessRow {
    pub id: String,
    pub name: String,
    /// 配置里声明的归属主机，顺序同配置。
    pub agents: Vec<String>,
    /// 其中存储里有序列的台数。
    pub agents_present: u64,
    /// 其中观察窗口内还在报的台数（`samples > 0`）。
    pub agents_reporting: u64,
    /// 配置里有、存储里没有：离线 / 从来没接入 / `agent` id 写错。
    pub agents_missing: Vec<String>,
    pub series: u64,
    pub processes: Option<f64>,
    pub cpu_cores: Option<f64>,
    pub load_1m_max: Option<f64>,
    pub memory_used_bytes: Option<f64>,
    pub memory_total_bytes: Option<f64>,
    pub disk_usage_max: Option<f64>,
    pub filesystem_usage_max: Option<f64>,
    pub collect_targets: Option<f64>,
    pub collect_dropped: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Middleware {
    pub families: Vec<MiddlewareFamily>,
}

/// 中间件的一层（家族）：契约里认识的那几家都列出来，没数据的 `metrics` 为空。
///
/// 为什么不由后端拼成「broker 卡 / 积压表」：布局是页面的事，而后端只需要把
/// 「哪些家族、哪些序列、当前值」说清楚。接口里 `instance` / `state` / `group` / `topic`
/// 这些 label 原样带出，前端按 `instance` 透视就行。
#[derive(Debug, Serialize)]
pub struct MiddlewareFamily {
    /// 契约里的家族名：`kafka` / `mysql` / `pg` / `doris` / `container`。
    pub kind: &'static str,
    pub label: &'static str,
    /// 指标名前缀（与 `wist-metrics` 的 collection_kind 同名）。
    pub prefix: &'static str,
    pub metrics: Vec<MiddlewareSample>,
}

#[derive(Debug, Serialize)]
pub struct MiddlewareSample {
    pub metric: String,
    pub value: f64,
    /// 序列 label（已去掉 `tenant_id`）：`instance` / `state` / `group` / `topic` / `agent`。
    pub labels: BTreeMap<String, String>,
}

/// `GET /api/metrics` — 概览：存储里有什么、谁在报、当前值是多少。
pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let principal = match authorize_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let tenant = match tenant_from_query(&state, &principal, query.as_deref()) {
        Ok(tenant) => tenant,
        Err(err) => return tenant_error(err),
    };
    let Some(config) = metrics_config(&state) else {
        return not_configured();
    };
    if let Err(response) = ensure_tenant_label(&state, &state.http, &config).await {
        return *response;
    }
    match collect_overview(&state.http, &config, &state.config.business, &tenant).await {
        Ok(value) => Json(value).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, "metrics_unavailable", err),
    }
}

/// 一条通道「累计写进来多少 + 最后一次是什么时候」。
///
/// 三条通道的单元本来就不一样：**证据按条**、**Atlas 按快照条数**、**指标按样本**。
/// 这里照原样报 `unit`，**不做单位换算** —— 强行统一成一种单位只能靠编。
///
/// 累计量由各服务自己的进程内计数器给（O(1)），所以看板可以秒级轮询；
/// 为什么不由 BFF 自己算：准确条数在各自的服务里（索引表 / 投递表），
/// 让 BFF 去翻页凑或直读别人的库，都是“看着对、量大了就错”。
/// 服务还没提供端点时就把 `note` 带回去，页面上显示得出来缺什么。
#[derive(Debug, Serialize)]
pub struct IngestChannel {
    /// `evidence` / `atlas` / `metrics`。
    pub id: &'static str,
    pub label: &'static str,
    /// 计数单位（`条` / `样本`）。
    pub unit: &'static str,
    /// **累计**写入量（自服务启动时的基线算起，含历史行）。
    ///
    /// 走服务端的进程内计数器（O(1)），所以可以秒级轮询；`None` = 这个通道没有累计概念。
    pub total: Option<f64>,
    /// 窗口内的量（仅在传了 `window_seconds > 0` 时给）。
    pub received: Option<f64>,
    /// 最后一次接收时间（unix 毫秒）。
    pub last_at_ms: Option<i64>,
    /// 拿不到的原因（只有 `total` 与 `received` 都为 `None` 时给）。
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IngestStats {
    /// 传 0 = 只看累计（看板实时轮询走这条，不触发任何窗口 count）。
    pub window_seconds: i64,
    pub checked_at_ms: i64,
    pub channels: Vec<IngestChannel>,
}

#[derive(Debug, Deserialize)]
pub struct IngestQuery {
    window_seconds: Option<i64>,
}

/// `GET /api/ingest/stats?window_seconds=` — 数据有没有进来、进来多少。
///
/// 与“接口可用性”的区别：探活 ok 只说明**端点通**，不代表**有数据在进来**。
/// 两件事在页面上必须分开摆，否则“配置对、上游没发”会看起来一切正常。
pub async fn ingest_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IngestQuery>,
    RawQuery(raw): RawQuery,
) -> Response {
    let principal = match authorize_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let tenant = match tenant_from_query(&state, &principal, raw.as_deref()) {
        Ok(tenant) => tenant,
        Err(err) => return tenant_error(err),
    };
    // `window_seconds=0` = 只看累计：看板实时轮询（3 秒）走这条，
    // 不触发服务端的窗口 count，也不向 VM 发 count_over_time。
    let requested = query.window_seconds.unwrap_or(0);
    let window = if requested > 0 {
        requested.clamp(MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS)
    } else {
        0
    };

    let evidence = evidence_ingest(&state, &tenant, window).await;
    let atlas = atlas_ingest(&state, &tenant, window).await;
    let metrics = metrics_ingest(&state, &tenant, window).await;

    Json(IngestStats {
        window_seconds: window,
        checked_at_ms: now_ms() as i64,
        channels: vec![evidence, atlas, metrics],
    })
    .into_response()
}

/// 证据：服务端的 `/internal/evidence/stats`（`{total, received, last_at_ms}`）。
async fn evidence_ingest(state: &AppState, tenant: &str, window: i64) -> IngestChannel {
    let mut channel = IngestChannel {
        id: "evidence",
        label: "证据",
        unit: "条",
        total: None,
        received: None,
        last_at_ms: None,
        note: None,
    };
    match state.evidence.stats(tenant, window).await {
        Ok(response) if response.status.is_success() => {
            let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            channel.total = body["total"].as_f64();
            channel.received = body["received"].as_f64();
            channel.last_at_ms = body["last_at_ms"].as_i64();
            if channel.total.is_none() && channel.received.is_none() {
                channel.note = Some("证据服务返回的计数为空".to_string());
            }
        }
        Ok(response) => {
            channel.note = Some(if response.status == StatusCode::NOT_FOUND {
                "证据服务还没有计数端点 /internal/evidence/stats（服务发版后这一行自动有数）"
                    .to_string()
            } else {
                format!("证据服务返回 {}", response.status.as_u16())
            });
        }
        Err(err) => channel.note = Some(format!("证据服务不可达：{err}")),
    }
    channel
}

/// Atlas：`/internal/atlas/stats`（`{total, received, last_at_ms}`；`ingest_job` 一行 = 一份快照）。
async fn atlas_ingest(state: &AppState, tenant: &str, window: i64) -> IngestChannel {
    let mut channel = IngestChannel {
        id: "atlas",
        label: "Atlas",
        unit: "条",
        total: None,
        received: None,
        last_at_ms: None,
        note: None,
    };
    let Some(atlas) = state.config.atlas.as_ref() else {
        channel.note = Some("BFF 没配 [atlas]".to_string());
        return channel;
    };
    let url = format!(
        "{}/internal/atlas/stats?window_seconds={window}&tenant={tenant}",
        atlas.base_url.trim_end_matches('/')
    );
    let mut request = state.http.get(&url);
    if let Some(token) = atlas.auth_token.as_deref() {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let body: Value = response.json().await.unwrap_or(Value::Null);
            channel.total = body["total"].as_f64();
            channel.received = body["received"].as_f64();
            channel.last_at_ms = body["last_at_ms"].as_i64();
            if channel.total.is_none() && channel.received.is_none() {
                channel.note = Some("Atlas 返回的计数为空".to_string());
            }
        }
        Ok(response) => {
            channel.note = Some(if response.status() == StatusCode::NOT_FOUND {
                "Atlas 还没有计数端点 /internal/atlas/stats（服务发版后这一行自动有数）".to_string()
            } else {
                format!("Atlas 返回 {}", response.status().as_u16())
            });
        }
        Err(err) => channel.note = Some(format!("Atlas 不可达：{err}")),
    }
    channel
}

/// 指标：VM 自己就能回答（窗口内样本数 + 最后一条样本时间），不需要服务改动。
///
/// 指标没有「累计行数」这个概念（VM 不保存写入了多少行的总账），所以 `total` 恒为 `None`；
/// 实时模式（`window=0`）只给「最后一次样本时间」，不断言条数。
async fn metrics_ingest(state: &AppState, tenant: &str, window: i64) -> IngestChannel {
    let mut channel = IngestChannel {
        id: "metrics",
        label: "运行指标",
        unit: "样本",
        total: None,
        received: None,
        last_at_ms: None,
        note: None,
    };
    let Some(config) = metrics_config(state) else {
        channel.note = Some("BFF 没配 [metrics]".to_string());
        return channel;
    };
    if !tenant.is_empty()
        && state.config.evidence.allowed_tenants.len() > 1
        && ensure_tenant_label(state, &state.http, &config)
            .await
            .is_err()
    {
        channel.note = Some("指标里没有 tenant_id label，无法按客户隔离查询".to_string());
        return channel;
    }
    if window > 0 {
        let samples = format!("sum(count_over_time({{__name__!=\"\"}}[{window}s]))");
        match query(&state.http, &config, &samples, tenant).await {
            Ok(result) => channel.received = result.first().and_then(scalar),
            Err(err) => channel.note = Some(format!("指标存储查询失败：{err}")),
        }
    }
    // 「最后一次样本」不能写成 `[0s]`（非法 range），也不能用瞬时查询：
    // 数据源停了以后 VM 会把这些序列标 stale，匹配全部指标的瞬时查询直接返回空，
    // 于是「三小时前停的」会变成「从来没有过」。所以一律用 `last_over_time`。
    //
    // 两段回退：先问 5 分钟（平稳时这一下就中，且按客户过滤后只扫自家的序列）；
    // 空了再问 1 小时 —— 只有真断了才会走第二段，平时 3 秒轮询不为它付代价。
    let lookbacks: Vec<String> = if window > 0 {
        vec![format!("{window}s")]
    } else {
        vec!["5m".to_string(), "1h".to_string()]
    };
    for lookback in lookbacks {
        let expr = format!("max(timestamp(last_over_time({{__name__!=\"\"}}[{lookback}])))");
        match query(&state.http, &config, &expr, tenant).await {
            // `timestamp()` 给的是秒，页面用毫秒。
            Ok(result) => {
                channel.last_at_ms = result.first().and_then(scalar).map(|s| (s * 1000.0) as i64);
                if channel.last_at_ms.is_some() {
                    break;
                }
            }
            Err(err) => {
                channel
                    .note
                    .get_or_insert(format!("指标存储查询失败：{err}"));
                break;
            }
        }
    }
    channel
}

/// `GET /api/metrics/middleware` — 中间件各家族的当前读数（Kafka / MySQL / PG / Doris / 容器）。
///
/// 指标页的「中间件」层不能只列指标名：那几个数字（broker 在不在、分区有没有离线、
/// 消费积压多少）才是要看的。这里按家族一次查询带回全部序列与当前值，
/// 布局（broker 卡 / 积压表）留给页面。
pub async fn middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let principal = match authorize_principal(&state, &headers) {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let tenant = match tenant_from_query(&state, &principal, raw.as_deref()) {
        Ok(tenant) => tenant,
        Err(err) => return tenant_error(err),
    };
    let Some(config) = metrics_config(&state) else {
        return not_configured();
    };
    if let Err(response) = ensure_tenant_label(&state, &state.http, &config).await {
        return *response;
    }
    match collect_middleware(&state.http, &config, &tenant).await {
        Ok(value) => Json(value).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, "metrics_unavailable", err),
    }
}

/// 契约里认识的中间件家族（`wist-metrics` 的 collection_kind）。
/// 没数据也列出来：页面要能说「契约在、采集没开」，而不是静默地少一层。
const MIDDLEWARE_FAMILIES: &[(&str, &str)] = &[
    ("kafka", "Kafka"),
    ("mysql", "MySQL / TiDB"),
    ("pg", "PostgreSQL"),
    ("doris", "Doris"),
    ("container", "容器"),
];

async fn collect_middleware(
    http: &reqwest::Client,
    base_url: &str,
    tenant: &str,
) -> Result<Middleware, String> {
    let mut families = Vec::new();
    for (prefix, label) in MIDDLEWARE_FAMILIES {
        let expr = format!("{{__name__=~\"{prefix}_.*\"}}");
        let result = query(http, base_url, &expr, tenant).await?;
        let mut metrics = Vec::new();
        for item in &result {
            let Some(metric) = item["metric"]["__name__"].as_str() else {
                continue;
            };
            let Some(value) = scalar(item) else {
                continue;
            };
            let labels = item["metric"]
                .as_object()
                .map(|object| {
                    object
                        .iter()
                        .filter(|(key, _)| {
                            key.as_str() != "__name__" && key.as_str() != "tenant_id"
                        })
                        .filter_map(|(key, value)| {
                            value.as_str().map(|value| (key.clone(), value.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            metrics.push(MiddlewareSample {
                metric: metric.to_string(),
                value,
                labels,
            });
        }
        families.push(MiddlewareFamily {
            kind: prefix,
            label,
            prefix,
            metrics,
        });
    }
    Ok(Middleware { families })
}

/// 数据面的指标里有没有 `tenant_id` label（按 `base_url` 缓存 60s）。
///
/// 为什么要缓：一个页面会并发发 4~5 条查询，每次都去拉一次 labels 是纯浪费；
/// 而 60s 足够让「刚绑完客户还没重启数据面」这种现场被发现。
async fn tenant_label_present(http: &reqwest::Client, base_url: &str) -> Result<bool, String> {
    if let Ok(cache) = label_cache().lock()
        && let Some((at, value)) = cache.get(base_url)
        && at.elapsed() < LABEL_CACHE_TTL
    {
        return Ok(*value);
    }
    let labels = get_json(http, &format!("{base_url}/api/v1/labels"), &[]).await?;
    let present = labels["data"]
        .as_array()
        .map(|labels| {
            labels
                .iter()
                .any(|label| label.as_str() == Some("tenant_id"))
        })
        .unwrap_or(false);
    if let Ok(mut cache) = label_cache().lock() {
        cache.insert(base_url.to_string(), (Instant::now(), present));
    }
    Ok(present)
}

/// 多客户站点：先确认指标里真有 `tenant_id` label，没有就**明确报错**。
///
/// 不拦的后果很阴：VM 里所有客户共用一个库，唯一的隔离手段就是这条 label；
/// 数据面没打标时查询只会返回空 —— 页面看起来像“这个客户没有指标”，人不会往
/// “网关没绑定租户”上想。单客户站点不拦（老数据可能没打标，别弄挂既有页面）。
/// `Response` 大到 clippy 不让直接当 `Err`（`result_large_err`），装箱。
async fn ensure_tenant_label(
    state: &AppState,
    http: &reqwest::Client,
    base_url: &str,
) -> Result<(), Box<Response>> {
    if state.config.evidence.allowed_tenants.len() <= 1 {
        return Ok(());
    }
    match tenant_label_present(http, base_url).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics_tenant_label_missing",
            "指标里没有 tenant_id label，多客户站点无法按客户隔离查询：\
             检查网关的租户绑定（WIST_TENANT_ID → WP_GLOBAL_TAGS）是否生效",
        ))),
        Err(err) => Err(Box::new(error_response(
            StatusCode::BAD_GATEWAY,
            "metrics_unavailable",
            err,
        ))),
    }
}

fn metrics_config(state: &AppState) -> Option<String> {
    state
        .config
        .metrics
        .as_ref()
        .map(|metrics| metrics.base_url.trim_end_matches('/').to_string())
}

fn not_configured() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "metrics_not_configured",
        "未配置 metrics.base_url（field-api.toml 的 [metrics] 段）：这个计算区还没有指标存储",
    )
}

const LABEL_CACHE_TTL: Duration = Duration::from_secs(60);

/// 每个 `metrics.base_url` 一份缓存（测试里会起多个桩端口，不能全局共用）。
fn label_cache() -> &'static Mutex<HashMap<String, (Instant, bool)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, bool)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 主机侧要展示的 fact（**用 fact_key 查 spec 表**，不手写指标名）。
/// `host.disk.*` 与 `host.filesystem.*` 不在同一个维度上：前者是整盘汇总，后者逐挂载点。
const HOST_FACTS: &[&str] = &[
    "host.info",
    "host.loadavg.1m",
    "host.loadavg.5m",
    "host.loadavg.15m",
    "host.memory.total_bytes",
    "host.memory.available_bytes",
    "host.memory.usage_ratio",
    "host.disk.system.usage_ratio",
    "host.disk.system.total_bytes",
    "host.disk.system.available_bytes",
    "host.filesystem.usage_ratio",
    "host.uptime.seconds",
    "process.pid",
];

fn spec_name(fact_key: &str) -> Option<&'static str> {
    METRIC_SPECS
        .iter()
        .find(|spec| spec.fact_key == fact_key)
        .map(|spec| spec.name)
}

/// 指标名 → fact_key 的反查（解析查询结果时用，避免在匹配分支里写死名字）。
fn fact_key(name: &str) -> Option<&'static str> {
    METRIC_SPECS
        .iter()
        .find(|spec| spec.name == name)
        .map(|spec| spec.fact_key)
}

fn names_for(facts: &[&str]) -> String {
    facts
        .iter()
        .filter_map(|fact| spec_name(fact))
        .collect::<Vec<_>>()
        .join("|")
}

async fn collect_overview(
    http: &reqwest::Client,
    base_url: &str,
    business: &[BusinessUnit],
    tenant: &str,
) -> Result<Value, String> {
    let self_metrics = format!(
        "{{__name__=~\"{}\"}}",
        agent_metric::ALL_SELF_METRICS.join("|")
    );
    // 主机侧单独一条查询：`system_*` / `process_*` 与 agent 自观测是两套序列。
    let host_metrics = format!("{{__name__=~\"{}\"}}", names_for(HOST_FACTS));
    // 目录与「每台 agent 有多少序列」都是一次全量计数：计算区的 VM 只收数据面镜像，
    // 规模是「几百到几千条序列」，与网关栈那份相比更小，不做额外分页。
    let catalog_expr = "count by (__name__) ({__name__=~\".+\"})".to_string();
    let per_agent_expr = format!("count by ({}) ({{__name__=~\".+\"}})", label::AGENT);
    let samples_expr = format!(
        "sum by ({}) (count_over_time({}[{}s]))",
        label::AGENT,
        agent_metric::CPU_RATIO,
        SAMPLE_WINDOW_SECONDS
    );

    // 四个查询并发：页面的四块信息互不依赖，串行只会把首页拖慢四倍。
    let (catalog, per_agent, values, host_values, samples) = tokio::join!(
        query(http, base_url, &catalog_expr, tenant),
        query(http, base_url, &per_agent_expr, tenant),
        query(http, base_url, &self_metrics, tenant),
        query(http, base_url, &host_metrics, tenant),
        query(http, base_url, &samples_expr, tenant),
    );
    // 任一失败就整页失败：半页数据比一句明确的报错更容易误导人。
    let mut catalog = catalog?;
    let per_agent = per_agent?;
    let values = values?;
    let host_values = host_values?;
    let samples = samples?;

    let mut entries: Vec<CatalogEntry> = catalog
        .drain(..)
        .filter_map(|item| {
            let name = item["metric"]["__name__"].as_str()?.to_string();
            let series = scalar(&item)? as u64;
            Some(CatalogEntry {
                group: name.split('_').next().unwrap_or(&name).to_string(),
                name,
                series,
            })
        })
        .collect();
    entries.sort_by(|left, right| {
        left.group
            .cmp(&right.group)
            .then(right.series.cmp(&left.series))
            .then(left.name.cmp(&right.name))
    });
    let total_series: u64 = entries.iter().map(|entry| entry.series).sum();

    let mut agents: BTreeMap<String, AgentRow> = BTreeMap::new();
    for item in &per_agent {
        let Some(agent_id) = item["metric"][label::AGENT].as_str() else {
            // 没有 `agent` 的序列（非 agent 写入的点）不属于任何一台机器。
            continue;
        };
        let row = agents.entry(agent_id.to_string()).or_default();
        row.agent_id = agent_id.to_string();
        row.series = scalar(item).unwrap_or(0.0) as u64;
    }
    for item in &samples {
        let Some(agent_id) = item["metric"][label::AGENT].as_str() else {
            continue;
        };
        if let Some(row) = agents.get_mut(agent_id) {
            row.samples = scalar(item).unwrap_or(0.0) as u64;
        }
    }
    for item in &values {
        let metric = &item["metric"];
        let Some(agent_id) = metric[label::AGENT].as_str() else {
            continue;
        };
        let name = metric["__name__"].as_str().unwrap_or_default();
        let value = scalar(item);
        let row = agents.entry(agent_id.to_string()).or_default();
        row.agent_id = agent_id.to_string();
        for key in SELECTION_LABELS {
            if let Some(found) = metric.get(*key).and_then(Value::as_str) {
                row.labels.insert((*key).to_string(), found.to_string());
            }
        }
        match name {
            agent_metric::CPU_RATIO => row.cpu_percent = value.map(ratio_to_percent),
            agent_metric::CPU_CORES => row.cpu_cores = value,
            agent_metric::MEMORY_BYTES => row.memory_bytes = value,
            agent_metric::ADMIN_LATENCY_SECONDS => {
                row.admin_latency_ms = value.map(seconds_to_millis).map(|ms| ms as f64);
            }
            agent_metric::COLLECT_TARGETS => {
                // 同一条指标按 `target_kind` × `outcome` 展开：这里按 outcome 汇总，
                // 保留「成功 / 丢弃」两个页面真正会看的数。
                if let Some(value) = value {
                    let dropped =
                        metric.get(label::OUTCOME).and_then(Value::as_str) == Some("dropped");
                    *row.collect_targets.get_or_insert(0.0) += value;
                    if dropped {
                        *row.collect_dropped.get_or_insert(0.0) += value;
                    }
                }
            }
            agent_metric::UPLINK_METRICS_FAILED_TOTAL => row.uplink_failed_total = value,
            agent_metric::DISCOVERY_POLICY_VERSION => row.discovery_policy_version = value,
            _ => {}
        }
    }

    // 主机侧（`system_*` / `process_*`）：按 fact_key 反查后再分支，不在代码里写指标名。
    for item in &host_values {
        let metric = &item["metric"];
        let Some(agent_id) = metric[label::AGENT].as_str() else {
            continue;
        };
        let name = metric["__name__"].as_str().unwrap_or_default();
        let value = scalar(item);
        let row = agents.entry(agent_id.to_string()).or_default();
        row.agent_id = agent_id.to_string();
        match fact_key(name) {
            Some("host.info") => {
                if let Some(found) = metric.get(label::HOST_NAME).and_then(Value::as_str) {
                    row.host.hostname = Some(found.to_string());
                }
                if let Some(found) = metric.get(label::HOST_IP).and_then(Value::as_str)
                    && !row.host.ip_addresses.iter().any(|ip| ip == found)
                {
                    row.host.ip_addresses.push(found.to_string());
                }
                row.host.os = metric
                    .get(label::OS)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or(row.host.os.clone());
                row.host.arch = metric
                    .get(label::ARCH)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or(row.host.arch.clone());
                row.host.kernel = metric
                    .get(label::KERNEL)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or(row.host.kernel.clone());
            }
            Some("host.loadavg.1m") => row.host.load_1m = value,
            Some("host.loadavg.5m") => row.host.load_5m = value,
            Some("host.loadavg.15m") => row.host.load_15m = value,
            Some("host.memory.total_bytes") => row.host.memory_total_bytes = value,
            Some("host.memory.available_bytes") => row.host.memory_available_bytes = value,
            Some("host.memory.usage_ratio") => {
                row.host.memory_usage_percent = value.map(ratio_to_percent)
            }
            Some("host.disk.system.usage_ratio") => {
                // `system_disk_usage_ratio` 按 `disk_role` 分两条序列（system / data）。
                if metric.get(label::DISK_ROLE).and_then(Value::as_str) == Some("system") {
                    row.host.disk_usage_percent = value.map(ratio_to_percent);
                }
            }
            Some("host.disk.system.total_bytes") => {
                if metric.get(label::DISK_ROLE).and_then(Value::as_str) == Some("system") {
                    row.host.disk_total_bytes = value;
                }
            }
            Some("host.disk.system.available_bytes") => {
                if metric.get(label::DISK_ROLE).and_then(Value::as_str) == Some("system") {
                    row.host.disk_available_bytes = value;
                }
            }
            Some("host.filesystem.usage_ratio") => {
                // 逐挂载点：只留最紧张的那个（页面一行装不下全部）。
                if let Some(ratio) = value
                    && let Some(mount) = metric.get(label::MOUNTPOINT).and_then(Value::as_str)
                {
                    let percent = ratio_to_percent(ratio);
                    if row
                        .host
                        .filesystem_usage_percent
                        .is_none_or(|current| percent > current)
                    {
                        row.host.filesystem_usage_percent = Some(percent);
                        row.host.filesystem_mount = Some(mount.to_string());
                    }
                }
            }
            Some("host.uptime.seconds") => row.host.uptime_seconds = value,
            Some("process.pid") => *row.host.processes.get_or_insert(0.0) += 1.0,
            _ => {}
        }
    }

    let (business, unassigned_agents) = business_rows(business, &agents);

    Ok(json!({
        "generated_at_ms": now_ms(),
        "window_seconds": SAMPLE_WINDOW_SECONDS,
        "source": { "base_url": base_url },
        "totals": {
            "names": entries.len(),
            "series": total_series,
            "agents": agents.len(),
        },
        "business": business,
        "unassigned_agents": unassigned_agents,
        "agents": agents.values().collect::<Vec<_>>(),
        "catalog": entries,
    }))
}

/// 业务层聚合：`(业务行, 未归类的主机)`。
fn business_rows(
    units: &[BusinessUnit],
    agents: &BTreeMap<String, AgentRow>,
) -> (Vec<BusinessRow>, Vec<String>) {
    let assigned: HashSet<&str> = units
        .iter()
        .flat_map(|unit| unit.agents.iter().map(String::as_str))
        .collect();

    let mut rows = Vec::with_capacity(units.len());
    for unit in units {
        let mut row = BusinessRow {
            id: unit.id.clone(),
            name: unit.name.clone(),
            agents: unit.agents.clone(),
            ..BusinessRow::default()
        };
        for agent_id in &unit.agents {
            let Some(agent) = agents.get(agent_id) else {
                row.agents_missing.push(agent_id.clone());
                continue;
            };
            row.agents_present += 1;
            if agent.samples > 0 {
                row.agents_reporting += 1;
            }
            row.series += agent.series;
            add_option(&mut row.processes, agent.host.processes);
            add_option(&mut row.cpu_cores, agent.cpu_cores);
            add_option(&mut row.collect_targets, agent.collect_targets);
            add_option(&mut row.collect_dropped, agent.collect_dropped);
            add_option(&mut row.memory_total_bytes, agent.host.memory_total_bytes);
            add_option(&mut row.memory_used_bytes, memory_used(&agent.host));
            max_option(&mut row.load_1m_max, agent.host.load_1m);
            max_option(&mut row.disk_usage_max, agent.host.disk_usage_percent);
            max_option(
                &mut row.filesystem_usage_max,
                agent.host.filesystem_usage_percent,
            );
        }
        rows.push(row);
    }

    let unassigned = agents
        .keys()
        .filter(|agent_id| !assigned.contains(agent_id.as_str()))
        .cloned()
        .collect();
    (rows, unassigned)
}

/// 累加：`None` 表示「没有任何一台主机报过这个维度」，与「和为 0」是两回事。
fn add_option(slot: &mut Option<f64>, value: Option<f64>) {
    if let Some(value) = value {
        *slot = Some(slot.map_or(value, |current| current + value));
    }
}

fn max_option(slot: &mut Option<f64>, value: Option<f64>) {
    if let Some(value) = value {
        *slot = Some(slot.map_or(value, |current| current.max(value)));
    }
}

/// 已用内存：优先 `total - available`（老 agentd 只报 total 时退回 `total × ratio`）。
fn memory_used(host: &HostMetrics) -> Option<f64> {
    match (host.memory_total_bytes, host.memory_available_bytes) {
        (Some(total), Some(available)) => Some((total - available).max(0.0)),
        (Some(total), None) => host
            .memory_usage_percent
            .map(|percent| total * percent / 100.0),
        _ => None,
    }
}

/// GET `/api/v1/query`，返回 `data.result`。
/// 把当前客户拼进 PromQL 的 label selector。
///
/// 为什么要在这里做：指标和证据一样按客户隔离，但它们都落在**同一个 VM** 里，
/// 唯一的区分是 `tenant_id` label（来自网关绑定的 `WP_GLOBAL_TAGS=tenant_id=<id>`）。
/// 本文件的表达式只有两种形态：`{...}` 与 `count by (x) ({...})`，所以逐 `{` 注入即可。
///
/// `tenant` 为空（不属于单客户站点的异常态）时原样返回 —— 宁可变回旧行为，也不拼出非法 PromQL。
fn scope_tenant(expr: &str, tenant: &str) -> String {
    let tenant = tenant.trim();
    if tenant.is_empty() {
        return expr.to_string();
    }
    let escaped = tenant.replace('\\', "\\\\").replace('"', "\\\"");
    let matcher = format!("tenant_id=\"{escaped}\"");
    let mut out = String::with_capacity(expr.len() + matcher.len() + 8);
    let mut rest = expr;
    while let Some(pos) = rest.find('{') {
        out.push_str(&rest[..=pos]);
        rest = &rest[pos + 1..];
        out.push_str(&matcher);
        if !rest.starts_with('}') {
            out.push_str(", ");
        }
    }
    out.push_str(rest);
    out
}

async fn query(
    http: &reqwest::Client,
    base_url: &str,
    expr: &str,
    tenant: &str,
) -> Result<Vec<Value>, String> {
    let url = format!("{base_url}/api/v1/query");
    let scoped = scope_tenant(expr, tenant);
    let payload = get_json(http, &url, &[("query", scoped.as_str())]).await?;
    Ok(payload["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

async fn get_json(
    http: &reqwest::Client,
    url: &str,
    params: &[(&str, &str)],
) -> Result<Value, String> {
    let response = http
        .get(url)
        .query(params)
        .timeout(QUERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("victoria metrics 请求失败：{err}"))?;
    if !response.status().is_success() {
        return Err(format!("victoria metrics 返回 HTTP {}", response.status()));
    }
    response
        .json()
        .await
        .map_err(|err| format!("victoria metrics 响应不是 JSON：{err}"))
}

/// 即时查询的标量值。VM 把值放在 `[时间戳, "值"]` 里，`NaN` / `Inf` 视为缺失。
fn scalar(item: &Value) -> Option<f64> {
    item["value"]
        .as_array()?
        .get(1)?
        .as_str()?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 主机侧的 fact_key 必须都能在 `wist-metrics` 的 spec 表里解析出指标名。
    /// 改名/删 spec 时这里先红，而不是页面上静默少几列。
    #[test]
    fn every_host_fact_resolves_to_a_metric_name() {
        for fact in HOST_FACTS {
            assert!(spec_name(fact).is_some(), "{fact} 不在 METRIC_SPECS 里");
        }
        // 反查也要能回来（解析查询结果时靠它分支）。
        for fact in HOST_FACTS {
            let name = spec_name(fact).expect("resolved");
            assert_eq!(fact_key(name), Some(*fact), "{fact} → {name} 反查不一致");
        }
    }

    #[test]
    fn scalar_ignores_non_finite_values() {
        assert_eq!(scalar(&json!({ "value": [1, "2.5"] })), Some(2.5));
        assert_eq!(scalar(&json!({ "value": [1, "NaN"] })), None);
        assert_eq!(scalar(&json!({})), None);
    }

    fn agent(id: &str, samples: u64, load_1m: f64, memory: (f64, f64)) -> AgentRow {
        let mut row = AgentRow {
            agent_id: id.to_string(),
            series: 10,
            samples,
            cpu_cores: Some(4.0),
            collect_targets: Some(5.0),
            ..AgentRow::default()
        };
        row.host.processes = Some(3.0);
        row.host.load_1m = Some(load_1m);
        row.host.memory_total_bytes = Some(memory.0);
        row.host.memory_available_bytes = Some(memory.1);
        row.host.disk_usage_percent = Some(60.0);
        row
    }

    #[test]
    fn business_rows_sum_where_it_adds_up_and_keep_peaks_as_peaks() {
        let mut agents = BTreeMap::new();
        agents.insert("a".to_string(), agent("a", 5, 1.5, (8.0, 2.0)));
        agents.insert("b".to_string(), agent("b", 0, 4.0, (8.0, 6.0)));
        agents.insert("c".to_string(), agent("c", 5, 0.5, (8.0, 4.0)));
        let units = vec![BusinessUnit {
            id: "billing".to_string(),
            name: "计费".to_string(),
            agents: vec!["a".to_string(), "b".to_string(), "gone".to_string()],
        }];

        let (rows, unassigned) = business_rows(&units, &agents);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.agents_present, 2);
        // 一台静默：业务里的「在报」不等于「有归属」。
        assert_eq!(row.agents_reporting, 1);
        assert_eq!(row.agents_missing, vec!["gone"]);
        assert_eq!(row.series, 20);
        // 可以跨机累加的量求和。
        assert_eq!(row.processes, Some(6.0));
        assert_eq!(row.cpu_cores, Some(8.0));
        assert_eq!(row.memory_used_bytes, Some(8.0));
        assert_eq!(row.memory_total_bytes, Some(16.0));
        // 单机口径的量取峰值，不相加。
        assert_eq!(row.load_1m_max, Some(4.0));
        assert_eq!(row.disk_usage_max, Some(60.0));
        // 没归属的主机单列，不默默漏掉。
        assert_eq!(unassigned, vec!["c".to_string()]);
    }
}

#[cfg(test)]
mod tenant_scope_tests {
    use super::scope_tenant;

    #[test]
    fn injects_the_tenant_into_every_selector() {
        assert_eq!(
            scope_tenant("count by (agent) ({__name__=~\".+\"})", "acme"),
            "count by (agent) ({tenant_id=\"acme\", __name__=~\".+\"})"
        );
        assert_eq!(
            scope_tenant("{__name__=~\"a|b\"}", "acme"),
            "{tenant_id=\"acme\", __name__=~\"a|b\"}"
        );
    }

    #[test]
    fn handles_an_empty_selector() {
        assert_eq!(
            scope_tenant("sum by (agent) (count_over_time({}[300s]))", "acme"),
            "sum by (agent) (count_over_time({tenant_id=\"acme\"}[300s]))"
        );
    }

    #[test]
    fn an_empty_tenant_keeps_the_expression_untouched() {
        let expr = "max by (agent) ({agent=\"a\"})";
        assert_eq!(scope_tenant(expr, ""), expr);
        assert_eq!(scope_tenant(expr, "   "), expr);
    }

    #[test]
    fn values_with_quotes_are_escaped() {
        assert_eq!(
            scope_tenant("{a=\"1\"}", "we\"ird"),
            "{tenant_id=\"we\\\"ird\", a=\"1\"}"
        );
    }
}
