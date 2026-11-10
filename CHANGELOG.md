# CHANGELOG

## 0.6.7 · 2026-11-11

- **`[metrics]` 新增 `write_url`（数据面视角的写入端点）**：与 `[atlas] sink_url` 同一性质 ——
  BFF 自己不用它，只透给「数据面接入」页 copy。`base_url` 保持 BFF 视角（栈内查询入口）不变。
- **`/api/integration` 新增 `metrics` 块**：
  `{ write_url, import_path, env, base_url }`，并把 `CONSOLE_VM_ENDPOINT` 一并放进
  `warp_parse.env`。变量名与导入路径是**协议事实**，收在 `api.rs` 两个常量里，
  页面不再手写 —— 原来页面写的是 `WIST_METRICS_ENDPOINT`，而数据面真正读的是
  `CONSOLE_VM_ENDPOINT`，两边对不上只会得到「接完了但没数据」。
- 没配 `write_url` 时回 `metrics: null`，**不编造占位地址**。

## 0.6.6 · 2026-11-09

- **`[verify].audience` 支持 `${…}` 展开**（与 `[init]` / `[publish]` 的字段同一机制）。
  audience 是**部署事实**：它必须等于 cred 侧那个 peer / 认证系统的名字，而不同站点往往
  用不同名字（例如 `local-field-alpha`）。以前只能改 `cred.toml` 本身，现在栈可以用
  `FIELD_API_AUDIENCE` 之类的变量渲染，站点在 `values/<系统>/sys_value.yml` 里设一次就行。
- 占位符解不开时启动期就报 `unresolved environment variable(s) in "…"`，不会拿占位符
  当 audience 继续跑 —— 那种情况 cred 侧只会得到 400 `audience_mismatch`，错在对端、极难查。
- 行为不变：不含 `${}` 的字面量原样使用（老配置零改动）。

## 0.6.5 · 2026-11-09

- **证据读接口的路径 key 改成「调查命令 id 优先」**：`GET /api/evidence/{cmd_id}`、
  `POST /api/evidence/{cmd_id}:presign`、`GET /api/evidence/{cmd_id}/content`。
  发起调查的人手里只有 `cmd_id`（证据 id 是不透明的、也不该由人转抄）；
  列表行里的 `artifact_id` 仍然可用 —— 定位规则在证据服务，BFF 只做路径安全校验与透传。
  路径参数名从 `artifact_id` 改成 `cmd_id`，URL 形状与鉴权不变。
- **列表支持 `?cmd_id=` 筛选**：`GET /api/evidence?cmd_id=cmd-...` 原样透传给证据服务，
  给页面的主筛选位用（命令 id 是发起调查的人手里唯一的关联键）。
- **新增 `GET /api/evidence/openapi.json`**：证据读接口的 OpenAPI 3.1 自述（列表 / 详情 /
  能力自述 / 正文代理读 / 预签名）。浏览器能调的就是这些 `/api/evidence*`，证据服务的
  `/internal/*` 不进去 —— 所以清单由 BFF 出，「接口可用性」页拿它渲染接口列表，
  页面不再需要另存一份（与 atlas 的 `/api/openapi.json` 同一个用法）。
- 端点与其它 `/api/*` 同一道门：要操作员身份（`401` 与业务接口一致）。
- **BFF 去读 atlas 时带令牌**：`field-api.toml` 的 `[atlas]` 新增 `auth_token`（通常是
  `${SEC_ATLAS_API_TOKEN}`）。atlas 从 0.3.4 起读接口要 `Authorization: Bearer`；
  浏览器仍然只持 BFF 的 `wcr_…` 令牌，atlas 的令牌只在本进程里。
  不配 = 对面是没开鉴权的老版本 atlas。
- 代理只发令牌，不做其他改写：atlas 的 401/404 原样透传给页面（不把上游的鉴权失败伪装成 BFF 的）。

## 0.6.4 · 2026-11-07

- **`/api/metrics` 新增「业务层」：主机集合 → 命名的逻辑单元**。`field-api.toml` 里配
  `[[business.units]]`（`id` / `name` / `agents`），响应多一个 `business` 数组：
  内存、进程、采集目标数**求和**，负载与磁盘使用率取**峰值**（它们本来就是单机口径，
  相加没有意义）。另外给出 `agents_present` / `agents_reporting` / `agents_missing` ——
  「配置里有、存储里没有」的主机不会被默默吃掉。
- **未归类主机单列**：`unassigned_agents` 列出不在任何业务里的主机，记到页面上而不是漏掉。
- **归属关系只存在于配置**，不下沉到数据面：agentd / wparse 的 label 契约不动，
  改归属不用重启数据面，也不需要 `tenant_id` / `biz` label。
- **一台主机只能属于一个业务**：跨业务共用会让投入（CPU / 内存 / 磁盘）重复计账，
  启动时直接报错。`id` 必填且唯一，`name` 留空时退回 `id`。
- 接口只做加法：新增字段，原有字段与语义不变；没配 `[[business.units]]` 时 `business` 是空数组。

## 0.6.3 · 2026-11-07

- **`/api/metrics` 新增主机侧数据**：每台 agent 多一个 `host` 块 —— 主机名 / IP / OS / 架构 / 内核、
  负载（1m/5m/15m）、内存（总量 / 可用 / 使用率）、系统盘使用率与容量、最紧张的挂载点、
  运行时长、采集到的进程数。
- **趋势多四条主机曲线**：1 分钟负载、主机内存使用率、系统盘使用率、最紧张挂载点使用率
  （`max by (__name__)` 折叠多挂载点）。仍排在 agent 自观测的四个之前。
- 指标名一律按 `fact_key` 查 `wist-metrics` 的 `METRIC_SPECS`，读侧不写死名字；
  新增一条单测钉住「每个 host fact 都能解析回指标名，且能反查」。
- 兼容：老 agentd 只报自观测时，`host` 里全为 `null`，页面显示「—」，不影响原有字段。

## 0.6.2 · 2026-11-07

- **TCR 推送从发版路径里拆出去**：`release.yml` 只推 ghcr（约 2 分钟出 tag + 多架构镜像），
  新增 `release-tcr.yml` 在同一 tag 上独立跑 TCR 同步。
- 起因：TCR 在腾讯云，从 GitHub runner 上传实测要 8~10 分钟（偶发 TLS 握手超时），
  把「推 tag → 镜像可用」从 2 分钟拖到 10 分钟以上；失败还会连累整条 Release。
- 现在 TCR 同步有独立 run，失败只重跑它，不影响已发布的 ghcr 镜像与 GitHub Release。
- **镜像内容与行为零变化**。

## 0.6.1 · 2026-11-06

- **发布流水线：原生分架构构建镜像，去掉 QEMU**（与 `wist-center` 同一套）：
  amd64 在 `ubuntu-24.04`、arm64 在 `ubuntu-24.04-arm` 各自原生构建；两个架构按 digest
  分别推 ghcr / TCR，最后由独立 job 在每个仓库内合并多架构 manifest（不跨仓库搬层）。
- 起因：0.6.0 的 `Build and push` 用了 **33 分钟** —— arm64 那一段在 amd64 runner 上模拟执行
  `apt-get`。改完预期 2~3 分钟。
- **镜像内容与行为零变化**（同基底、同二进制、同入口、同 tag 规则）。

## 0.6.0 · 2026-11-06

- **改名：`wist-console` → `wist-field-api`**（crate / 二进制 / 镜像同名）：
  - 环境变量：`WIST_CONSOLE_CONFIG` → `WIST_FIELD_CONFIG`、`WIST_CONSOLE_SEC_FILE` → `WIST_FIELD_SEC_FILE`；
  - 配置文件名：`console.toml` → `field-api.toml`（示例改为 `field-api.example.toml`）；
  - 错误码前缀：`console_*` → `field_*`（`field_operator_missing` / `field_credential_*` /
    `field_role_required` / `field_credential_store_unavailable` / `field_upstream_failed`）；
  - ingress 操作员头：`x-console-operator` → `x-field-operator`。
- **凭据侧一起改**：`cred.toml` 的 `audience` 改为 `wist-field-api`，栈侧密钥项
  `SEC_CONSOLE_PEER_SETUP_CODE` → `SEC_FIELD_API_PEER_SETUP_CODE`。
  ⚠ 这是一次**重新接入**：在 cred 里新建 `wist-field-api` 认证系统并签发新令牌，
  旧的 `wist-console` 令牌与摘要全部失效（令牌需重发，不需要改代码）。
- HTTP 接口路径与业务逻辑**零变更**。

## 0.5.0 · 2026-11-06

- **新增 `GET /api/evidence/capabilities`**：把证据服务 `/healthz` 的 `objects.kind` 转成
  页面能用的形状 `{ objects_kind, presign_supported }`。
- `presign_supported = false`（`objects.kind = file`）时，证据页「打开正文」直接走 BFF
  代理读（`/api/evidence/{id}/content`），不再先发一个必然 501 的签名请求。
- 证据服务不报 `objects`（老实例）/ 探测失败时回 `objects_kind: null` +
  `presign_supported: true`，页面保持「先试签名、失败再回落」。

## 0.4.0 · 2026-11-06

- **新增运行指标读接口**：`GET /api/metrics`（存储里有什么、谁在报、即时值）与
  `GET /api/metrics/agents/{agent_id}/history`（单台趋势）。读的是**计算区自己那份**
  VictoriaMetrics —— 数据面把 agent 采集指标镜像到这里；网关栈那份仍只服务控制面观测页。
- **口径收在 BFF**：指标名 / label 键 / 单位换算取自 `wist-metrics`（读侧不再手写名字），
  CPU 换算成百分比、时延换算成毫秒；用 `count_over_time` 判「采集静默」，窗口 5m–24h、
  步长 10–900s 自动夹紧，并按点数上限放宽步长。
- 未配置 `[metrics].base_url` 时返回 `503 metrics_not_configured`（那是「这一域还没接」，
  不是故障）。引擎 / 管道统计（`wparse_*`）只写网关栈，不在本服务范围内。

## 0.3.1 · 2026-11-06

- **`/api/integration` 不再下发连接器定义**：`warp_parse` 只保留 `env`（写端点地址），
  去掉 `connector` / `sink_group` —— 数据面接入统一复用现成的 `http_sink`，
  不再引导为证据 / atlas 各建一个 `[[connectors]]`。写端点、字段约定与允许的 kind 不变。

## 0.3.0 · 2026-11-05

- **新增 `POST /api/login`**：把访问令牌换成「你是谁 + 给了什么角色」
  （`{credential_id, subject, roles, audience, expires_at}`）。契约由 `wist-cred-peer` 0.5
  统一：401 `credential_missing` / `credential_invalid`、403 `role_required`、
  503 `credential_store_unavailable`。其它接口仍是每请求 Bearer —— 登录只回答“这串是谁”，
  不换 session。前端据此能把「令牌不对」和「角色不够」分开说。
- **修 0.2.0 的自注册启动死锁**：`require_signature = true` + 尚未初始化 + 公钥不在时，
  原来是启动期拒 —— 但公钥是自注册时随 bundle 下发的，于是进程起不来、永远打不开 `/__init`。
  现在只在**未初始化**时延后验签（WARN + 健康页写出来）；已初始化仍缺公钥照样拒启动。
- **运行期降级状态显式可见**：材料在运行中被删 → `is_initialized()` 立刻变 false，
  但 listener 还握着启动时加载的证书。503 响应体与健康页都会说“重新注册后必须**重启**”。
- `client-ca.pem` 在、但读不了（权限/损坏）→ 启动期报错。原来会滑进“未初始化”分支：
  cred-peer 认为已初始化（`/__init` 回 409），listener 又起不来，表现成“一切正常但推不进来”。
- 依赖 `wist-cred-peer` **0.5**。
- 用例：单测 23、契约 16。

## 0.2.1 · 2026-11-05

- 修 0.2.0 里两个「配了但没生效」——都是靠真配置启动才发现的那类：
  1. **`[publish].endpoint` 没做 `${VAR}` 展开**：栈渲染的
     `https://${CONSOLE_ADVERTISE_HOST}:…` 会被原样当成主机名，证书能签出来、注册也“成功”，
     真错要等 cred 拨号才暴露（而且错在对方）。现在启动期就展开，变量没渲染则当场报
     `unresolved environment variable`；
  2. `[verify].require_signature` / `[init].insecure_tls` 只认 TOML 字面 bool，栈没法用变量切。
     现在字面 `true` 与字符串 `"true"` / `"${VAR}"` 都认；值不认识就是启动期错误，
     不退化成“默认关掉一个安全开关”。
- 没开验签时不再为“公钥还没下发”打 `warn`（那是新部署的正常状态），
  只在“文件在但读不了”时告警。

## 0.2.0 · 2026-11-05

- **自注册（P1）**：`cred.toml` 可以不带 `[identity]`，只给 `[init]` + `[publish]` ——
  首次启动只开 `/__init`，由本服务自己向 cred 登记并把三件材料写进 cred.toml 同目录；
  材料齐了收数监听**自己起来**（`serve_when_ready`），不需要重启进程。
- **未初始化时业务面一律 `503 peer_not_initialized`**（`/healthz` 仍通，否则容器会被
  健康检查拖进无限重启）。以前这种状态只会表现为“页面能开、接口永远 401”。
- `[init].setup_code` 支持 `${SEC_…}`：`cred.toml` 不走 BFF 的 `RawConfig`，但秘密仍
  从同一个密钥文件展开；没展开成功就启动期报错，不退化成空口令。
- `[init].ca_file` / `insecure_tls` 原样交给 `wist-cred-peer`（入口自签的信任锚，或确知跳过）；
  变量渲染出来的空 `ca_file` 按“没配”处理。
- 启动错误带上 `cred.toml` 路径；`publish_endpoint` 没主机名、`[identity]`/`[init]` 都没有
  这类配置错，都在启动期就拒。
- 依赖 `wist-cred-peer` **0.4**（P1 的 `ca_file` / `serve_when_ready` 在 0.3 里没有）。

## 0.1.13 · 2026-11-05

- **凭据状态进了「接口可用性」**：`/api/health` 多一条 `credentials`，直接读本进程的两个事实 ——
  收数监听在不在、摘要表登记了几条。三种状态说得很直白：
  `已登记 N 条凭据；收数监听 x:3103 在线` / `一条凭据都没登记：检查 cred 侧的 endpoint`
  / `收数监听不在运行`。下次「cred 那边注册了但推不进来」在页面上就能看出来，不用猜。

## 0.1.12 · 2026-11-05

- 启动时如果摘要表**一条都没登记**，打一条 `warn` 并指出两个常见原因
  （peer 没配 endpoint / cred 到不了 listener）—— 否则现象只是「令牌全 401」，无从下手。

## 0.1.11 · 2026-11-05

- **接入 `wist-cred-peer` 做认证与授权，删掉 `dev`（不校验）模式**。
  `auth.mode = "cred"`（默认）：浏览器带 `Authorization: Bearer wcr_…`，BFF 用摘要表验；
  `cred` 通过 mTLS 把 `{digest, subject, roles, expires_at, signature}` 推到
  `credentials.listen_addr`（默认 3103），**只落 sha256**，重启不丢、撤销不复活。
- 401 / 403 分开：没带 token → `console_credential_missing`；不认识 / 过期 / 撤销 →
  `console_credential_invalid`（对外不区分原因）；角色不够 → `console_role_required`。
- `auth.mode = "ingress"` 保留：入口已经做了认证、并能保证头不被伪造时可用。
- 配置 fail-closed：`mode = "cred"` 但缺 `[credentials]`、`cred.toml` 读不到、
  `required_roles` 不在 `[verify].roles` 里 —— 都在**启动期**报错，不带病运行。
- **资产读接口收进 BFF**：新增 `GET /api/atlas/{*path}` → `{atlas.base_url}/api/{path}`。
  以前 `/atlas/api/*` 由 nginx 直连 atlas-web，等于给令牌认证留了个后门；
  现在与其它接口同一道门。只放行 GET，`/internal/*` 与路径穿越一律 400。

## 0.1.10 · 2026-11-05

- 新增 `[metrics] base_url`（VictoriaMetrics）：`/api/health` 多一条「运行指标存储」探活，
  `sources.metrics` 从 `not_configured` 变成真实状态。
- `[atlas]` 新增 `sink_url`（**数据面视角**的写端点），`/api/integration` 多一块 `atlas` 接入示例
  （两字段 `{cust_id, content}`，`content` 是 DSNAP 记录），`warp_parse.env` 相应多一个 `ATLAS_SINK_URL`。
- atlas 的 `/healthz` 现在也带 `probe` 块，接口可用性页会像证据写端点一样显示
  「写探针 N 秒前成功」——两条写链路同一套判据。

## 0.1.9 · 2026-11-05

- `/api/integration` 改成**三字段契约**：示例记录是 `{cust_id, cmd_id, content}`，
  连接器不再带 `username` / `password`，`env` 只剩 `EVIDENCE_SINK_URL`；
  sink 分组名改成 `evidence-uplink`（与 `wist-console-stack` 的示例对齐）。
- 「接口可用性」的写端点检查会读证据服务 `/healthz` 的 `probe` 块，直接显示
  「写探针 12 秒前成功（3 ms）」，而不是只说「端口通」。

## 0.1.8 · 2026-11-04

- 代理读正文的响应补 `cache-control: no-store` 与 `x-content-type-options: nosniff`：
  证据正文不能被浏览器 / 中间代理缓存。

## 0.1.7 · 2026-11-04

- 新增 `GET /api/evidence/{artifact_id}/content`：代理读正文。
  证据服务 `objects.kind = file` 时不签发预签名 URL（`:presign` 回 501），页面改用这条拿原文；
  BFF 依旧不缓存、不落盘，浏览器依旧不持任何凭据。

## 0.1.6 · 2026-11-04

- 接口可用性变成**可观测的功能**：`/api/health.interfaces[]` 每条多一个 `covers`，
  写明这一次探活验到了哪一层（页面直接展示，不让「绿」含糊）。
- 证据读端点改用**真读**探活（`GET /internal/evidence?limit=1`，带服务身份）：
  鉴权、租户/敏感度闸与 PG 索引都会被验到；不再只戳 `/healthz`。
- 写端点探活只验端口就绪，**不发测试写入**（不往证据库塞垃圾）。

## 0.1.5 · 2026-11-04

- `/api/health` 新增 `interfaces`：逐条探活 `evidence_read` / `evidence_write` / `atlas`，
  回状态、延迟（`latency_ms`）与最近检查时间（`checked_at_ms`）。三个探活**并发**发，
  一个上游挂掉不会把另外两条的延迟一起拖长。
- 新增配置项 `integration.sink_health_url`：**BFF 视角**的写端点探活地址。
  它与 `integration.sink_url` 不是一回事 —— 后者是给数据面看的（BFF 到不了）。
  没配时写端点显示 `not_configured` 并说明缺哪个配置项。
- `sources.atlas` 不再单独发一次探测：直接复用 `interfaces` 里那次结果。

## 0.1.4 · 2026-11-02

- 新增 `GET /api/integration`：给「数据面接入」页返回写端点、认证方式、允许的 kind，
  以及两份可直接 copy 的 wparse 配置（连接器 + sink 分组）。**不返回站点 token**。

## 0.1.3 · 2026-11-02

- `/api/health` 的数据源键 `pipeline` 改名 `metrics`（运行指标），与前端路由 `#/metrics` 对齐。

## 0.1.2 · 2026-11-02

- 镜像构建改用 `wist-gateway` 的同一套做法：release 流水线按平台**原生**编译二进制，
  镜像只打包 `docker/amd64` / `docker/arm64`，不再在镜像内编译。
- 运行镜像改为 `ubuntu:24.04` + `busybox-static`，uid 固定 10001。
- GitHub Release 附带三个平台的原生二进制 tarball。

## 0.1.1 · 2026-11-02

- 修正运行时镜像：`busybox:stable` 需要 glibc 2.38，bookworm 只有 2.36，容器健康检查会
  直接报 `GLIBC_2.38 not found`；改用静态的 `busybox:stable-musl`。

## 0.1.0 · 2026-11-02

首个骨架：计算区运维台的 BFF。

- `GET /api/health`：聚合证据 / atlas / 采集量 / 设备状态的就绪度（后两者显式 `not_configured`）；
- `GET /api/evidence`、`GET /api/evidence/{id}`、`POST /api/evidence/{id}:presign`：
  透传证据服务，状态码与 JSON 原样返回；
- 到证据服务的身份（租户 / scope / 敏感度）只来自配置，URL 里的 `tenant` 被丢弃；
- 入口身份：`ingress` 模式要求操作者头，`dev` 仅用于本机；
- 不缓存正文、不代理正文、不自己做授权判断。
