//! `wist-field-api` 进程入口。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use wist_field_api::api::{self, AppState};
use wist_field_api::config::{AuthMode, Config};
use wist_field_api::credentials;
use wist_field_api::upstream::EvidenceClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config_path = std::env::args().nth(1);
    let config = Config::load(config_path.as_deref().map(Path::new))?;

    // 凭据运行时：启动期就把 mTLS 建好（证书缺失 / 链不对 → 直接拒启，
    // 不出现「业务面只认凭据、凭据 listener 起不来」的半启用状态）。
    let credentials = match (&config.credentials, config.auth.mode) {
        (Some(credentials_config), AuthMode::Cred) => Some(Arc::new(
            credentials::build(credentials_config)
                .map_err(|err| anyhow::anyhow!("credentials: {err}"))?,
        )),
        // 配了材料却选了 ingress：不装 listener，但要说一声 —— 否则运维会以为
        // `wist-cred` 推得进来，实际上一辈子都是空的。
        (Some(_), AuthMode::Ingress) => {
            log::warn!(
                "[credentials] is configured but auth.mode = ingress: the push listener is NOT started"
            );
            None
        }
        _ => None,
    };
    if let Some(runtime) = credentials.as_ref() {
        credentials::spawn_listener(Arc::clone(runtime));
    }

    let evidence = EvidenceClient::new(&config.evidence)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.evidence.timeout_secs))
        .build()?;

    log::info!(
        "wist-field-api starting: listen={} auth={:?} evidence={} atlas={}",
        config.server.listen_addr,
        config.auth.mode,
        config.evidence.base_url,
        config
            .atlas
            .as_ref()
            .map(|atlas| atlas.base_url.as_str())
            .unwrap_or("(none)")
    );
    // 租户态：多客户站点最常见的问题就是“页面 400/403 但不知道为什么”，
    // 启动时把“有几个可选客户”打出来，比现场猜配置快得多。
    log::info!(
        "evidence tenants: default={} allowed={} {}",
        config
            .evidence
            .default_tenant
            .as_deref()
            .unwrap_or("(none)"),
        config.evidence.allowed_tenants.len(),
        if config.evidence.allowed_tenants.len() > 1 {
            "(multi-customer: requests must pass ?tenant=<id>)"
        } else {
            "(single-customer site)"
        }
    );

    let state = AppState {
        config: Arc::new(config.clone()),
        evidence: Arc::new(evidence),
        http,
        credentials,
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&config.server.listen_addr)
        .await
        .with_context(|| format!("bind {}", config.server.listen_addr))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
