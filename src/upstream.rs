//! 证据服务的上游客户端。
//!
//! 只做三件事：拼 URL、带上**服务自己的**身份头、把状态码与正文原样交回去。
//! **不缓存**正文、不改写响应、不替证据服务做授权判断。

use std::time::Duration;

use axum::http::StatusCode;
use reqwest::{Client, Method};

use crate::config::EvidenceConfig;

#[derive(Debug)]
pub struct EvidenceClient {
    http: Client,
    base_url: String,
    /// 单客户站点的兜底租户（多客户部署里每次请求带自己的，见 `send`）。
    default_tenant: Option<String>,
    scopes: String,
    max_sensitivity: String,
}

#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl EvidenceClient {
    pub fn new(config: &EvidenceConfig) -> anyhow::Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;
        Ok(Self {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            default_tenant: config.default_tenant.clone(),
            scopes: config.scopes.join(","),
            max_sensitivity: config.max_sensitivity.clone(),
        })
    }

    /// 单客户站点的兜底租户（`/healthz` 这种不需要租户的调用用它）。
    fn fallback_tenant(&self) -> &str {
        self.default_tenant.as_deref().unwrap_or_default()
    }

    /// `tenant` 必须是**服务端算出来的**（`Principal::resolve_tenant`），绝不直接用浏览器传的值。
    async fn send(
        &self,
        method: Method,
        path_and_query: &str,
        tenant: &str,
    ) -> Result<UpstreamResponse, String> {
        let url = format!("{}{}", self.base_url, path_and_query);
        let response = self
            .http
            .request(method, &url)
            // 身份来自服务端（配置/授权解析），**不接受**浏览器传参（D7 的同一条纪律）。
            .header("x-evidence-tenant", tenant)
            .header("x-evidence-scopes", &self.scopes)
            .header("x-evidence-max-sensitivity", &self.max_sensitivity)
            .send()
            .await
            .map_err(|err| format!("request {url} failed: {err}"))?;
        let status =
            StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let body = response
            .bytes()
            .await
            .map_err(|err| format!("read upstream body failed: {err}"))?
            .to_vec();
        Ok(UpstreamResponse { status, body })
    }

    pub async fn list(
        &self,
        tenant: &str,
        query: Option<&str>,
    ) -> Result<UpstreamResponse, String> {
        let path = match query.filter(|value| !value.is_empty()) {
            Some(query) => format!("/internal/evidence?{query}"),
            None => "/internal/evidence".to_string(),
        };
        self.send(Method::GET, &path, tenant).await
    }

    /// 部署自述（`GET /healthz`）：当前只取 `objects.kind`，`probe` 细节不转给前端。
    /// 证据服务的 `/healthz` 不看租户，这里传兜底值只为了不把 header 弄空。
    pub async fn health(&self) -> Result<UpstreamResponse, String> {
        self.send(Method::GET, "/healthz", self.fallback_tenant())
            .await
    }

    pub async fn get(&self, tenant: &str, key: &str) -> Result<UpstreamResponse, String> {
        self.send(Method::GET, &format!("/internal/evidence/{key}"), tenant)
            .await
    }

    /// 短签名。`key` 可以是证据 id 或调查命令 id（定位规则在证据服务）。
    pub async fn presign(&self, tenant: &str, key: &str) -> Result<UpstreamResponse, String> {
        self.send(
            Method::POST,
            &format!("/internal/evidence/{key}:presign"),
            tenant,
        )
        .await
    }

    /// 代理读正文（`GET /internal/evidence/{key}/content`）。
    /// 预签名不可用的部署（证据服务 `objects.kind = file`）走这条。
    pub async fn content(&self, tenant: &str, key: &str) -> Result<UpstreamResponse, String> {
        self.send(
            Method::GET,
            &format!("/internal/evidence/{key}/content"),
            tenant,
        )
        .await
    }
}
