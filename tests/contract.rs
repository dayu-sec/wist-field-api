//! BFF 契约测试：身份头、透传语义、健康聚合。
//!
//! 上游是**进程内真 HTTP**（同一个 axum），不 mock：要验的正是"头有没有真的带上"。

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, RawQuery};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use wist_field_api::api::{self, AppState};
use wist_field_api::config::{
    AtlasConfig, AuthConfig, AuthMode, Config, EvidenceConfig, IntegrationConfig, MetricsConfig,
    ServerConfig,
};
use wist_field_api::upstream::EvidenceClient;

fn config(base_url: String, mode: AuthMode) -> Config {
    Config {
        server: ServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
        },
        auth: AuthConfig {
            mode,
            operator_header: "x-console-operator".to_string(),
        },
        credentials: None,
        evidence: EvidenceConfig {
            base_url,
            tenant: "t-001".to_string(),
            scopes: vec!["evidence:read".to_string()],
            max_sensitivity: "paths".to_string(),
            timeout_secs: 5,
        },
        atlas: None,
        metrics: None,
        integration: IntegrationConfig {
            sink_url: None,
            sink_health_url: None,
            allowed_kinds: vec!["investigation_report".to_string()],
        },
        business: Vec::new(),
    }
}

fn state(config: Config) -> AppState {
    let evidence = EvidenceClient::new(&config.evidence).expect("evidence client");
    AppState {
        config: Arc::new(config),
        evidence: Arc::new(evidence),
        http: reqwest::Client::new(),
        credentials: None,
    }
}

async fn stub_list(headers: HeaderMap, RawQuery(query): RawQuery) -> axum::Json<Value> {
    axum::Json(json!({
        "artifacts": [],
        "next_cursor": null,
        "seen_query": query,
        "seen_tenant": headers.get("x-evidence-tenant").and_then(|v| v.to_str().ok()),
        "seen_scopes": headers.get("x-evidence-scopes").and_then(|v| v.to_str().ok()),
        "seen_sensitivity": headers.get("x-evidence-max-sensitivity").and_then(|v| v.to_str().ok()),
    }))
}

async fn stub_get(Path(artifact_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({ "artifact_id": artifact_id, "kind": "investigation_report" }))
}

async fn stub_presign(Path(raw): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({
        "artifact_id": raw.trim_end_matches(":presign"),
        "url": "memory://objects/x?expires=1",
        "expires_in_seconds": 60,
        "expires_at": "2026-11-02T00:00:00Z",
    }))
}

/// 代理读正文：证据服务直接把原文交回来（本地文件模式没有签名 URL）。
async fn stub_content(Path(artifact_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({ "artifact_id": artifact_id, "body": "original-report" }))
}

/// VictoriaMetrics 的 `/api/v1/query` 桩：按 PromQL 的形状回不同结果。
///
/// 真实 VM 的响应形状就是 `{data:{result:[{metric:{…}, value:[ts,"v"]}]}}`；
/// 这里只需要把 BFF 的四种查询（目录 / 每 agent 序列数 / 即时值 / 样本数）区分开。
async fn stub_vm_query(Query(params): Query<HashMap<String, String>>) -> axum::Json<Value> {
    let expr = params.get("query").cloned().unwrap_or_default();
    let result = if expr.contains("count by (__name__)") {
        json!([
            { "metric": { "__name__": "agent_cpu_ratio" }, "value": [1_700_000_000, "1"] },
            { "metric": { "__name__": "system_memory_total_bytes" }, "value": [1_700_000_000, "1"] },
        ])
    } else if expr.contains("count_over_time") {
        json!([{ "metric": { "agent": "agent-a" }, "value": [1_700_000_000, "10"] }])
    } else if expr.contains("count by (agent)") {
        json!([{ "metric": { "agent": "agent-a" }, "value": [1_700_000_000, "42"] }])
    } else {
        json!([
            {
                "metric": { "__name__": "agent_cpu_ratio", "agent": "agent-a", "env": "dev" },
                "value": [1_700_000_000, "0.0816"]
            },
            {
                "metric": { "__name__": "agent_memory_bytes", "agent": "agent-a", "env": "dev" },
                "value": [1_700_000_000, "104857600"]
            },
            {
                "metric": { "__name__": "agent_cpu_cores", "agent": "agent-a", "env": "dev" },
                "value": [1_700_000_000, "8"]
            },
            {
                "metric": { "__name__": "agent_admin_latency_seconds", "agent": "agent-a", "env": "dev" },
                "value": [1_700_000_000, "0.0153"]
            },
            {
                "metric": {
                    "__name__": "agent_collect_targets",
                    "agent": "agent-a",
                    "target_kind": "host",
                    "outcome": "succeeded"
                },
                "value": [1_700_000_000, "3"]
            },
            {
                "metric": {
                    "__name__": "agent_collect_targets",
                    "agent": "agent-a",
                    "target_kind": "process",
                    "outcome": "dropped"
                },
                "value": [1_700_000_000, "1"]
            },
        ])
    };
    axum::Json(json!({ "status": "success", "data": { "resultType": "vector", "result": result } }))
}

/// VictoriaMetrics 的 `/api/v1/query_range` 桩：四条自观测指标各一串。
async fn stub_vm_range(Query(params): Query<HashMap<String, String>>) -> axum::Json<Value> {
    let expr = params.get("query").cloned().unwrap_or_default();
    // 请求里带了 agent 过滤：BFF 必须把 URL 里的 id 拼进 PromQL。
    assert!(expr.contains("agent-a"), "{expr}");
    axum::Json(json!({
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": { "__name__": "agent_cpu_ratio", "agent": "agent-a", "env": "dev" },
                    "values": [[1_700_000_000, "0.5"], [1_700_000_030, "1.0"]]
                },
                {
                    "metric": { "__name__": "agent_memory_bytes", "agent": "agent-a", "env": "dev" },
                    "values": [[1_700_000_000, "104857600"], [1_700_000_030, "209715200"]]
                },
                {
                    "metric": { "__name__": "agent_cpu_cores", "agent": "agent-a", "env": "dev" },
                    "values": [[1_700_000_000, "8"], [1_700_000_030, "8"]]
                },
                {
                    "metric": { "__name__": "agent_admin_latency_seconds", "agent": "agent-a", "env": "dev" },
                    "values": [[1_700_000_000, "0.015"], [1_700_000_030, "0.25"]]
                }
            ]
        }
    }))
}

async fn spawn_stub() -> String {
    spawn_stub_with_healthz(json!({ "status": "ok", "objects": { "kind": "file" } })).await
}

/// 同一个桩，但指定证据服务 `/healthz` 的正文 ——
/// 用来验「老证据服务不报 `objects` 时不把能力当成不支持」。
async fn spawn_stub_with_healthz(healthz_body: Value) -> String {
    let app = Router::new()
        .route(
            "/healthz",
            get(move || {
                let body = healthz_body.clone();
                async move { axum::Json(body) }
            }),
        )
        // VictoriaMetrics 的健康端点（console 的 metrics 探活用）。
        .route("/health", get(|| async { "OK" }))
        .route("/api/v1/query", get(stub_vm_query))
        .route("/api/v1/query_range", get(stub_vm_range))
        // atlas 的读接口（console 以 `/api/atlas/*` 代理过去）。
        .route(
            "/api/hosts",
            get(|| async { axum::Json(json!({ "status": "ok", "data": { "hosts": [] } })) }),
        )
        .route("/internal/evidence", get(stub_list))
        .route(
            "/internal/evidence/{artifact_id}",
            get(stub_get).post(stub_presign),
        )
        .route(
            "/internal/evidence/{artifact_id}/content",
            get(stub_content),
        )
        // 证据服务开了写探针时的 /healthz 形状。
        .route(
            "/probe-healthz",
            get(|| async {
                axum::Json(json!({
                    "status": "ok",
                    "probe": {
                        "last_ok": true,
                        "last_at_ms": 1_700_000_000_000u64,
                        "last_latency_ms": 3,
                        "consecutive_failures": 0,
                        "purged_total": 7
                    }
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let address = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("oneshot");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn list_is_passed_through_and_tenant_is_stripped() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence?tenant=t-999&kind=investigation_report")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 浏览器传的 tenant 必须被丢掉；真正生效的是配置里的身份。
    assert_eq!(body["seen_query"], "kind=investigation_report");
    assert_eq!(body["seen_tenant"], "t-001");
    assert_eq!(body["seen_scopes"], "evidence:read");
    assert_eq!(body["seen_sensitivity"], "paths");
}

#[tokio::test]
async fn list_filter_by_command_id_is_passed_through() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence?cmd_id=cmd-filter-1")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 命令 id 是页面上的主筛选位：BFF 必须原样透传给证据服务。
    assert_eq!(body["seen_query"], "cmd_id=cmd-filter-1");
}

#[tokio::test]
async fn missing_operator_header_is_401() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "field_operator_missing");
}

#[tokio::test]
async fn cred_mode_rejects_a_missing_bearer_token() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Cred)));
    let request = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    // 没有「不校验」这一档：cred 模式下没 token 就是 401，且原因与「token 不认识」分开。
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "field_credential_missing");
}

#[tokio::test]
async fn presign_is_passed_through() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .method("POST")
        .uri("/api/evidence/art_01ABC:presign")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["artifact_id"], "art_01ABC");
    assert_eq!(body["expires_in_seconds"], 60);
}

#[tokio::test]
async fn a_command_id_is_passed_through_as_the_read_key() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let command_id = "cmd_agent-001_investigate_45";

    // 发起调查的人手里只有命令 id：BFF 不能把它当成非法证据 id 排掉。
    let request = Request::builder()
        .uri(format!("/api/evidence/{command_id}"))
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["artifact_id"], command_id);

    // 签名 / 正文走同一条定位规则（`{cmd_id}:presign` 由路由整体吃下来）。
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/evidence/{command_id}:presign"))
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["artifact_id"], command_id);
}

#[tokio::test]
async fn evidence_openapi_describes_the_browser_facing_read_surface() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));

    // 和别的 `/api/*` 一样只有一道门：没有令牌就不给清单。
    let request = Request::builder()
        .uri("/api/evidence/openapi.json")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let request = Request::builder()
        .uri("/api/evidence/openapi.json")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["openapi"], "3.1.0");
    assert_eq!(body["info"]["title"], "数据场 · 证据读取 API");

    // 清单里必须是浏览器**真能调**的路径（证据服务 `/internal/*` 不能出现在这里）。
    for path in [
        "/api/evidence",
        "/api/evidence/capabilities",
        "/api/evidence/{cmd_id}",
        "/api/evidence/{cmd_id}:presign",
        "/api/evidence/{cmd_id}/content",
    ] {
        assert!(body["paths"].get(path).is_some(), "missing {path}: {body}");
    }
    // 详情读的路径参数是**调查命令 id**：发起调查的人手里只有它（证据 id 只做兼容）。
    assert_eq!(
        body["paths"]["/api/evidence/{cmd_id}"]["get"]["parameters"][0]["name"],
        "cmd_id"
    );
    // 列表页也是 cmd_id 主位：第一个查询参数就是它。
    assert_eq!(
        body["paths"]["/api/evidence"]["get"]["parameters"][0]["name"],
        "cmd_id"
    );
    assert_eq!(
        body["paths"]["/api/evidence/{cmd_id}:presign"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/PresignResult"
    );
    // 文档级鉴权：页面据此给每个接口打「需要令牌」。
    assert_eq!(body["security"][0]["bearerAuth"], json!([]));
}

#[tokio::test]
async fn health_reports_unconfigured_domains() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base.clone(), AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sources"]["evidence"]["status"], "ok");
    assert_eq!(body["sources"]["atlas"]["status"], "not_configured");
    assert_eq!(body["sources"]["metrics"]["status"], "not_configured");
    assert_eq!(body["sources"]["devices"]["status"], "not_configured");

    // 接口可用性：读端点探的是一次**真实读**（鉴权 + PG 索引都会走到），
    // 写端点与 atlas 没配地址时显式 `not_configured`。
    let interfaces = body["interfaces"].as_array().expect("interfaces array");
    assert_eq!(interfaces.len(), 5, "{body}");
    assert_eq!(interfaces[0]["id"], "evidence_read");
    assert_eq!(interfaces[0]["status"], "ok", "{body}");
    assert!(interfaces[0]["latency_ms"].is_u64());
    assert!(interfaces[0]["checked_at_ms"].is_u64());
    // 读端点探的是一次真读（不是只戳 /healthz），且告诉页面这一次验到了哪一层。
    assert_eq!(
        interfaces[0]["url"],
        format!("{base}/internal/evidence?limit=1")
    );
    assert!(!interfaces[0]["covers"].as_str().unwrap_or("").is_empty());
    assert_eq!(interfaces[1]["id"], "evidence_write");
    assert_eq!(interfaces[1]["status"], "not_configured");
    assert_eq!(interfaces[2]["id"], "atlas");
    assert_eq!(interfaces[2]["status"], "not_configured");
    assert_eq!(interfaces[3]["id"], "metrics");
    assert_eq!(interfaces[3]["status"], "not_configured");
    // 凭据：ingress 模式不参与认证，但条目要在，页面才知道这一域存在。
    assert_eq!(interfaces[4]["id"], "credentials");
    assert_eq!(interfaces[4]["status"], "not_configured");
}

#[tokio::test]
async fn interfaces_are_probed_when_configured() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base.clone(),
        auth_token: None,
        sink_url: None,
    });
    cfg.integration.sink_health_url = Some(format!("{base}/healthz"));
    cfg.metrics = Some(MetricsConfig {
        base_url: base.clone(),
        write_url: None,
    });
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for entry in body["interfaces"].as_array().expect("interfaces array") {
        // `credentials` 看的是本进程手里的状态，不发请求，所以没有延迟；
        // 这个用例只验「配了地址的都能探通」。
        if entry["id"] == "credentials" {
            assert_eq!(entry["status"], "not_configured", "{body}");
            continue;
        }
        assert_eq!(entry["status"], "ok", "{body}");
        assert!(entry["latency_ms"].is_u64(), "{body}");
    }
}

#[tokio::test]
async fn integration_page_shows_the_sink_contract() {
    let base = spawn_stub().await;
    let mut cfg = config(base, AuthMode::Ingress);
    cfg.integration.sink_url = Some("http://10.0.0.5:18800".to_string());
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/integration")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["evidence"]["write_url"],
        "http://10.0.0.5:18800/internal/evidence"
    );
    assert_eq!(body["evidence"]["auth"], "none");
    // 租户就是客户：这一格现在给的是客户 id。
    assert_eq!(body["evidence"]["customer"], "t-001");
    assert_eq!(body["evidence"]["record"]["cust_id"], "t-001");
    assert_eq!(body["evidence"]["record"]["cmd_id"], "cmd-20261105-001");

    // 接入页不再下发连接器定义：统一复用现成的 `http_sink`，BFF 只给环境变量。
    assert!(body["warp_parse"]["connector"].is_null());
    assert!(body["warp_parse"]["sink_group"].is_null());
    assert_eq!(
        body["warp_parse"]["env"]["EVIDENCE_SINK_URL"],
        "http://10.0.0.5:18800"
    );
}

#[tokio::test]
async fn integration_page_shows_the_metrics_endpoint_from_config() {
    // 运行指标的接入样板不能再手写地址：写端点来自 `[metrics] write_url`，
    // 变量名与导入路径来自 BFF 的一处常量。
    let base = spawn_stub().await;
    let mut cfg = config(base, AuthMode::Ingress);
    cfg.metrics = Some(MetricsConfig {
        base_url: "http://metrics:8428".to_string(),
        write_url: Some("http://10.0.0.5:18428/".to_string()),
    });
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/integration")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 尾斜杠被去掉：页面会自己拼 `${ENV}/api/v1/import`。
    assert_eq!(body["metrics"]["write_url"], "http://10.0.0.5:18428");
    assert_eq!(body["metrics"]["import_path"], "/api/v1/import");
    assert_eq!(body["metrics"]["env"], "CONSOLE_VM_ENDPOINT");
    // 数据面进程要看到的环境变量同步下发。
    assert_eq!(
        body["warp_parse"]["env"]["CONSOLE_VM_ENDPOINT"],
        "http://10.0.0.5:18428"
    );
}

#[tokio::test]
async fn metrics_block_is_null_when_no_dataplane_address_is_configured() {
    // 没配就**不展示写入样板**，而不是编一个占位地址 ——
    // 占位地址被 copy 出去就是「接完了但没数据」。
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.metrics = Some(MetricsConfig {
        base_url: base,
        write_url: None,
    });
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/integration")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["metrics"].is_null());
    assert!(body["warp_parse"]["env"]["CONSOLE_VM_ENDPOINT"].is_null());
}

#[tokio::test]
async fn atlas_is_probed_when_configured() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base,
        auth_token: None,
        sink_url: None,
    });
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sources"]["atlas"]["status"], "ok");
}

#[tokio::test]
async fn capabilities_report_the_file_backend() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/capabilities")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // `objects.kind = file`：没有签名 URL，页面直接走 BFF 代理读，不再先撞一次 501。
    assert_eq!(body["objects_kind"], "file", "{body}");
    assert_eq!(body["presign_supported"], false, "{body}");
}

#[tokio::test]
async fn capabilities_leave_the_old_behaviour_when_the_backend_is_unknown() {
    // 老证据服务的 /healthz 不报 `objects`：不能因此把签名路径判死，
    // 否则切回 s3 的部署反而读不了正文。
    let base = spawn_stub_with_healthz(json!({ "status": "ok" })).await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/capabilities")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["objects_kind"].is_null(), "{body}");
    assert_eq!(body["presign_supported"], true, "{body}");
}

#[tokio::test]
async fn capabilities_require_the_operator_header() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/capabilities")
        .body(Body::empty())
        .unwrap();
    let (status, _) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn content_is_proxied_through_the_bff() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/art_01ABC/content")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // 原文由 BFF 从证据服务取回、原样交出；浏览器不碰预签名 URL。
    assert_eq!(body["artifact_id"], "art_01ABC");
    assert_eq!(body["body"], "original-report");
}

#[tokio::test]
async fn content_requires_the_operator_header() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/art_01ABC/content")
        .body(Body::empty())
        .unwrap();
    let (status, _) = call(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn proxied_content_is_not_cacheable() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let request = Request::builder()
        .uri("/api/evidence/art_01ABC/content")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    // 证据正文不能进浏览器 / 中间代理的缓存。
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
}

#[tokio::test]
async fn write_interface_reports_the_probe() {
    // 证据服务的 /healthz 带 probe 块时，接口可用性那一行要能看出「真的写进去了」。
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.integration.sink_health_url = Some(format!("{base}/probe-healthz"));
    let app = api::router(state(cfg));
    let request = Request::builder()
        .uri("/api/health")
        .header("x-console-operator", "zhangsan")
        .body(Body::empty())
        .unwrap();
    let (status, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let write = body["interfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .find(|entry| entry["id"] == "evidence_write")
        .expect("evidence_write entry");
    let detail = write["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("写探针"), "{detail}");
    assert!(detail.contains("成功"), "{detail}");
}

#[tokio::test]
async fn atlas_reads_go_through_the_bff() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.atlas = Some(AtlasConfig {
        base_url: base,
        auth_token: None,
        sink_url: None,
    });
    let app = api::router(state(cfg));

    // 没有身份 → 401：资产数据面与其它 /api/* 是同一道门。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/atlas/hosts")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // 有身份 → 透传 atlas 的响应，并加 no-store。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/atlas/hosts")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["hosts"].as_array().unwrap().len(), 0);

    // 写端点前缀（/internal/*）不经过 BFF 暴露给浏览器。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/atlas/internal/atlas")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "atlas_path_invalid");
}

/// 自注册闸门：没有 cred 材料时业务面一律 503，只留 `/__init`（与容器的 `/healthz`）。
///
/// 这一条防的是"半可用现场"：页面能打开、接口永远 401，运维只能猜。
#[tokio::test]
async fn an_uninitialized_service_serves_only_the_init_page() {
    let dir = std::env::temp_dir().join(format!(
        "wist-console-init-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0),
        // macOS 的 `SystemTime` 只到微秒：只靠时间戳，两个测试会撞同一目录。
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        }
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cred_file = dir.join("cred.toml");
    std::fs::write(
        &cred_file,
        r#"
[verify]
audience = "wist-console"
allowed_issuers = ["wist-cred"]
roles = ["read"]

[init]
setup_code = "crp_test_setup_code"

[publish]
endpoint = "https://console.internal:18802/api/v1/internal/credentials"
"#,
    )
    .expect("cred.toml");

    let runtime = wist_field_api::credentials::build(&wist_field_api::config::CredentialsConfig {
        file: cred_file,
        listen_addr: "127.0.0.1:0".to_string(),
        store_path: dir.join("credentials.json"),
        required_roles: vec!["read".to_string()],
    })
    .expect("credentials");
    assert!(!runtime.is_initialized());

    let base = spawn_stub().await;
    let mut app_state = state(config(base, AuthMode::Cred));
    app_state.credentials = Some(Arc::new(runtime));
    let app = api::router(app_state);

    // 业务面 → 503，并给出可执行的下一步（去 /__init），而不是 401。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/evidence")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "peer_not_initialized");

    // 容器的健康检查不能被闸门拦住，否则 compose 会一直重启。
    let (status, _) = call(
        &app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 初始化页本身可用。
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/__init")
            .header("accept", "application/json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "uninitialized");

    // 登录端点也在这道门后面：没材料时连令牌都没得验。
    let (status, body) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"token":"wcr_x"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "peer_not_initialized");

    let _ = std::fs::remove_dir_all(&dir);
}

/// 运行中把材料删掉 → 门后面的 503 要说清「重新注册后必须重启」。
///
/// 这条文案是现场**唯一**能看到的状态描述：`/api/health` 自己也在这道门后面。
#[tokio::test]
async fn deleting_materials_at_runtime_is_reported_in_the_503_body() {
    fn write_materials(dir: &std::path::Path) {
        use wist_pki::CertificateAuthority;
        wist_pki::tls::install_crypto_provider();

        let (authority, ca_pem, _key) = CertificateAuthority::generate("Stub CA").expect("ca");
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "console.internal".to_string());
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let issued = authority
            .issue_server_certificate(&csr, &["console.internal".to_string()], 3600)
            .expect("issue");
        std::fs::write(dir.join("server.crt"), &issued.certificate_pem).expect("cert");
        std::fs::write(dir.join("server.key"), key.serialize_pem()).expect("key");
        std::fs::write(dir.join("client-ca.pem"), &ca_pem).expect("ca");
    }

    let dir = std::env::temp_dir().join(format!(
        "wist-console-gone-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0),
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        }
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    write_materials(&dir);
    let cred_file = dir.join("cred.toml");
    std::fs::write(
        &cred_file,
        r#"
[identity]
cert = "server.crt"
key = "server.key"
client_ca = "client-ca.pem"

[verify]
audience = "wist-console"
allowed_issuers = ["wist-cred"]
roles = ["read"]
"#,
    )
    .expect("cred.toml");

    let runtime = Arc::new(
        wist_field_api::credentials::build(&wist_field_api::config::CredentialsConfig {
            file: cred_file,
            listen_addr: "127.0.0.1:0".to_string(),
            store_path: dir.join("credentials.json"),
            required_roles: vec!["read".to_string()],
        })
        .expect("credentials"),
    );
    assert!(runtime.is_initialized());

    let base = spawn_stub().await;
    let mut app_state = state(config(base, AuthMode::Cred));
    app_state.credentials = Some(runtime);
    let app = api::router(app_state);

    for name in ["server.crt", "server.key", "client-ca.pem"] {
        std::fs::remove_file(dir.join(name)).expect("remove");
    }

    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/evidence")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "peer_not_initialized");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("RESTART"), "{message}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// 登录端点：把令牌换成身份/权限（由 `wist-cred-peer` 提供契约）。
///
/// 这里只验“宿主挂对了、状态码与错误码符合契约”；令牌有效/角色不足/摘要表故障
/// 由 `wist-cred-peer` 自己的用例覆盖（它才是这段逻辑的归属地）。
#[tokio::test]
async fn login_endpoint_reports_the_peer_contract() {
    fn write_materials(dir: &std::path::Path) {
        use wist_pki::CertificateAuthority;
        wist_pki::tls::install_crypto_provider();

        let (authority, ca_pem, _key) = CertificateAuthority::generate("Stub CA").expect("ca");
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "console.internal".to_string());
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let issued = authority
            .issue_server_certificate(&csr, &["console.internal".to_string()], 3600)
            .expect("issue");
        std::fs::write(dir.join("server.crt"), &issued.certificate_pem).expect("cert");
        std::fs::write(dir.join("server.key"), key.serialize_pem()).expect("key");
        std::fs::write(dir.join("client-ca.pem"), &ca_pem).expect("ca");
    }

    let dir = std::env::temp_dir().join(format!(
        "wist-console-login-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0),
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        }
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    write_materials(&dir);
    let cred_file = dir.join("cred.toml");
    std::fs::write(
        &cred_file,
        r#"
[identity]
cert = "server.crt"
key = "server.key"
client_ca = "client-ca.pem"

[verify]
audience = "wist-console"
allowed_issuers = ["wist-cred"]
roles = ["read"]
"#,
    )
    .expect("cred.toml");

    let runtime = Arc::new(
        wist_field_api::credentials::build(&wist_field_api::config::CredentialsConfig {
            file: cred_file,
            listen_addr: "127.0.0.1:0".to_string(),
            store_path: dir.join("credentials.json"),
            required_roles: vec!["read".to_string()],
        })
        .expect("credentials"),
    );

    let base = spawn_stub().await;
    let mut app_state = state(config(base, AuthMode::Cred));
    app_state.credentials = Some(runtime);
    let app = api::router(app_state);

    // 没带令牌 → 401 credential_missing（不是“field_credential_*”：这是登录端点，
    // 契约由 cred-peer 统一，中心/ingest 接入时同一个语义）。
    let (status, body) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/login")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "credential_missing");

    // 令牌不认识 → 401 credential_invalid（不区分过期/撤销/audience）。
    let (status, body) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"token":"wcr_nope"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "credential_invalid");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn metrics_page_reads_the_compute_zone_victoria_metrics() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.metrics = Some(MetricsConfig {
        base_url: base.clone(),
        write_url: None,
    });
    let app = api::router(state(cfg));

    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/metrics")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // 存储目录：名字 + 序列数（页面按前缀分组）。
    assert_eq!(body["totals"]["names"], 2, "{body}");
    assert_eq!(body["totals"]["series"], 2, "{body}");
    assert_eq!(body["totals"]["agents"], 1, "{body}");
    assert_eq!(body["window_seconds"], 300);

    // 即时值：单位在 BFF 就换算成页面口径（百分比 / 毫秒），前端不做算术。
    let agent = &body["agents"][0];
    assert_eq!(agent["agent_id"], "agent-a");
    assert_eq!(agent["labels"]["env"], "dev");
    assert_eq!(agent["series"], 42);
    assert_eq!(agent["samples"], 10);
    assert!((agent["cpu_percent"].as_f64().unwrap() - 8.16).abs() < 1e-6);
    assert_eq!(agent["cpu_cores"], 8.0);
    assert_eq!(agent["memory_bytes"], 104_857_600.0);
    assert_eq!(agent["admin_latency_ms"], 15.0);
    // 采集记账按 outcome 汇总；`target_kind` 不进身份 label。
    assert_eq!(agent["collect_targets"], 4.0);
    assert_eq!(agent["collect_dropped"], 1.0);
    assert!(agent["labels"].get("target_kind").is_none(), "{body}");
}

#[tokio::test]
async fn metrics_history_is_normalized_per_agent() {
    let base = spawn_stub().await;
    let mut cfg = config(base.clone(), AuthMode::Ingress);
    cfg.metrics = Some(MetricsConfig {
        base_url: base.clone(),
        write_url: None,
    });
    let app = api::router(state(cfg));

    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/metrics/agents/agent-a/history?window_seconds=900&step_seconds=15")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["agent_id"], "agent-a");
    assert_eq!(body["window_seconds"], 900);
    assert_eq!(body["step_seconds"], 15);
    assert_eq!(body["labels"]["env"], "dev");

    let series = body["series"].as_array().expect("series");
    assert_eq!(series.len(), 4, "{body}");
    // 顺序跟常量表（`wist-metrics` 的 `agent::HISTORY`）走：页面横排四张图，顺序要稳定。
    assert_eq!(series[0]["metric"], "agent_memory_bytes");
    assert_eq!(series[0]["unit"], "bytes");
    assert_eq!(series[1]["metric"], "agent_cpu_ratio");
    assert_eq!(series[1]["unit"], "percent");
    assert_eq!(series[1]["points"][0][0], 1_700_000_000_000i64);
    assert_eq!(series[1]["points"][0][1], 50.0);
    assert_eq!(series[1]["points"][1][1], 100.0);
    assert_eq!(series[3]["metric"], "agent_admin_latency_seconds");
    assert_eq!(series[3]["unit"], "milliseconds");
    assert_eq!(series[3]["points"][1][1], 250.0);
}

#[tokio::test]
async fn metrics_without_a_store_is_503_not_an_error_page() {
    let base = spawn_stub().await;
    let app = api::router(state(config(base, AuthMode::Ingress)));
    let (status, body) = call(
        &app,
        Request::builder()
            .uri("/api/metrics")
            .header("x-console-operator", "zhangsan")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    // 「这一域还没接」与「存储坏了」必须分开：前者是 503 + 明确缺哪个配置项。
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "metrics_not_configured");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("metrics.base_url")
    );
}
