# wist-field-api

计算区运维台的 **BFF**。浏览器只跟它说话：到证据服务的 mTLS / 租户 / scope / 敏感度
全在这里，页面不持有任何凭据。

设计：`wist-design/doc/design/console/console-architecture.md`（历史路径，仓名已去掉 console）
前端：[`wist-field-web`](https://github.com/dayu-sec/wist-field-web)（展示名「数据场 · 现场视图」）
部署：[`wist-field-stack`](https://github.com/dayu-sec/wist-field-stack)

## 接口

```text
POST /api/login
     体：{ token } 或 `Authorization: Bearer wcr_…`
     → { credential_id, subject, roles, audience, expires_at }
     契约由 `wist-cred-peer`（≥0.5）统一：401 `credential_missing` / `credential_invalid`，
     403 `role_required`，503 `credential_store_unavailable`。
     其它接口仍然每请求带 Bearer —— 登录只负责"先确认这串是谁"，不换 session。

GET  /api/health
     → { status, sources: { evidence|atlas|metrics|devices: { status, detail? } },
         interfaces: [{ id, label, covers, url?, status, detail?, latency_ms?, checked_at_ms? }] }

GET  /api/evidence?cmd_id=&kind=&subject_id=&since=&limit=&cursor=
     → 透传证据服务的 { artifacts, next_cursor }
       `cmd_id` 是主筛选位：发起调查时拿到的命令 id，只看这次调查的产物。

GET  /api/evidence/capabilities
     → { objects_kind: "file"|"s3"|null, presign_supported: bool }
       证据服务 `/healthz` 的 `objects.kind` 转成页面能用的形状：
       `presign_supported = false`（本地文件存储）时页面直接走代理读，
       不再先发一个必然 501 的签名请求；后端不报时退回「先试签名、失败再回落」。

GET  /api/evidence/openapi.json
     → OpenAPI 3.1：浏览器能调的证据读接口（列表 / 详情 / 能力自述 / 正文代理读 / 预签名）。
       证据服务的 `/internal/*` 不进 spec —— 浏览器到不了，身份由 BFF 从配置里带。
       「接口可用性」页拿它渲染接口列表（与 atlas 的 `/api/openapi.json` 同一个用法）。

GET  /api/evidence/{cmd_id}
     → 透传证据服务的索引行
       path 里的 key 是**调查命令 id**（发起调查的人手里只有这个）；
       列表行里的证据 id（`art_…`）也接受 —— 证据服务先按证据 id 再按命令 id 找。

GET  /api/evidence/{cmd_id}/content
     → 代理读正文（本地文件模式没有预签名时走这条）

POST /api/evidence/{cmd_id}:presign
     → 透传证据服务的 { artifact_id, url, expires_in_seconds, expires_at }

GET  /api/integration
     → { evidence: { write_url, auth, allowed_kinds, ... },
         warp_parse: { connector, sink_group, env } }

GET  /api/metrics
     → { generated_at_ms, window_seconds, source, totals,
         business: [...], unassigned_agents: [...], agents: [...], catalog: [...] }
     读的是**本栈** VictoriaMetrics（数据面把 agent 采集指标镜像进来），不是网关栈那份。

GET  /api/metrics/agents/{agent_id}/history?window_seconds=&step_seconds=
     → { agent_id, window_seconds, step_seconds, labels, series: [{ metric, title, unit, points }] }
     窗口 5m–24h、步长 10–900s（越界自动夹紧）；单位已在 BFF 换算成 percent / milliseconds / bytes。
```

`sources` 是「这个域接没接上」；`interfaces` 是「这条接口此刻通不通」——逐条探活
（`evidence_read` / `evidence_write` / `atlas`），带延迟、检查时间与 `covers`（这次到底验到了哪一层）。
三个探活并发发，一个上游挂掉不会拖长另外两个；没配地址的接口返回 `not_configured`，并说明缺哪个配置项。

## 三条纪律

1. **浏览器不持凭据**：`evidence.tenant` / `scopes` / `max_sensitivity` 只来自配置；
   URL 里带的 `tenant` 参数会被丢掉。
2. **不做二次判断**：证据服务回 `404` 就回 `404`（不区分「不存在」和「无权看」），
   BFF 不自己拼授权结论。
3. **不落正文**：预签名 URL 直接透传，BFF 不缓存、不代理正文；需要流式读时另开
   `/api/evidence/{id}/content`（P1），不在这个骨架上顺手加。

## 运行指标

两份 VictoriaMetrics **互不聚合**（谁写谁查）：

- 网关栈那份：`WPARSE_VM_ENDPOINT`，给控制面观测页，含引擎 / 管道统计（`wparse_*`）；
- 本栈那份（`[metrics] base_url`）：数据面用 `CONSOLE_VM_ENDPOINT` 把 **同一批 agent 采集指标**
  再写一份，给数据场（`wist-field-web`）的「运行指标」页。

所以本栈的序列数少于网关栈是正常的 —— 差值正是只写网关栈的引擎统计。指标名 / label 键 /
单位换算全部取自 `wist-metrics` 的 `names` 常量表，读侧不再手写名字（历史上曾因此整页空白）。
没配 `[metrics]` 时这一域回 `503 metrics_not_configured`（「没接入」，不是故障）。

### 四层表达

页面按四层看这一片的「强度」，BFF 只负责第 1 层的聚合：

| 层 | 数据来源 | 说明 |
| --- | --- | --- |
| 1 业务层 | `field-api.toml` 的 `[[business.units]]` | 主机集合 → 命名的逻辑单元 |
| 2 服务层 | 指标的 `app` label | `app` 表达**用途**；同一用途可落在多台主机 |
| 3 中间件层 | `container_*` / `kafka_*` | 有契约，等 agentd 开 provider |
| 4 计算资源层 | `system_*` / `process_*` | 宿主侧资源 |

**业务单元 ≠ `app`**：`app` 是用途（这台机器上跑什么），业务单元是归属（这台机器的开销算到
哪条业务上）。归属关系只存在于配置里，**不下沉到数据面** —— agentd / wparse 的 label 契约
不动，改归属不用重启数据面，也不需要 `tenant_id` / `biz` label。

```toml
[[business.units]]
id    = "billing"          # 必填且唯一
name  = "计费服务"          # 留空时退回 id
agents = ["agent-host-a55a338d7723"]   # 指标里的 `agent` label
```

规则与口径：

- 一台主机**只能属于一个业务**（跨业务共用会让投入重复计账，启动时直接报错）；
- 不在任何业务里的主机列在 `unassigned_agents`，不默默漏掉；
- 内存 / 进程 / 采集目标数 / 核数**求和**；负载与磁盘 / 挂载点使用率取**峰值** —— 后两者
  本来就是单机口径，相加没有意义；
- 配置里有、存储里没有的主机（离线 / 从没接入 / id 写错）放在 `agents_missing`。

口径注意：`agent_cpu_ratio` 是**瞬时比例**，算投入（core·小时）要先在 VM 里
`sum by (agent) (rate(system_cpu_seconds_total{mode!="idle"}[5m]))` 再按业务相加，
不能用这一层给的瞬时值乘时间。

## 入口身份

`auth.mode = "cred"`（默认）：请求带 `Authorization: Bearer wcr_…`，摘要由 `wist-cred` 通过
mTLS 推到 `credentials.listen_addr`（默认 `3103`），BFF 用 `wist-cred-peer` 验；没有 token → 401，
角色不够 → 403。
`auth.mode = "ingress"`：交给入口（VPN / 堡垒机 / 反代）认证，再把操作员写在 `x-field-operator` 里。
**没有「不校验」这一档** —— 一个计算区界面不该默认谁都能进。

## 运行

```bash
cargo run -- field-api.example.toml
# 或 WIST_FIELD_CONFIG=/etc/wist-field-api/field-api.toml wist-field-api
```

端口：容器内 `8080`（由 field-web 的 nginx 反代 `/api`）。

## 构建

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

镜像是**打包预编译二进制**（与 `wist-gateway` 同构，不在镜像里编译）：

```bash
# Linux 开发机：先编原生二进制再打包
cargo build --release --locked --target aarch64-unknown-linux-gnu
mkdir -p docker/arm64 && cp target/aarch64-unknown-linux-gnu/release/wist-field-api docker/arm64/
docker build -t wist-field-api:dev docker
```

日常直接用 CI 产物：`ghcr.io/dayu-sec/wist-field-api:v0.6.0-alpha`。
镜像以 `10001:10001` 运行；挂进来的配置 0644，`sec-value.yml` 0640 且属主为 10001。
