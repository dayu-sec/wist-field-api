# ===========================================================================
# wist-field-api — 运行镜像（多架构）
#
# 与 `wist-gateway` 同一套做法：二进制由 release 流水线按平台**原生**编译，
# build context（本目录）按 `amd64/` `arm64/` 提供，镜像只负责打包。
#
# ⚠ 不要在这个 Dockerfile 里引 `apt-get`：
#   `ubuntu:24.04` 已自带 `useradd`，运行期真正缺的只有「根证书 + 静态 busybox」，
#   而这两样直接从现成镜像拷比跑 `apt-get update` 少一个构建期网络依赖。
#   2026-11-11 的实际故障：GitHub runner 的 buildkit 容器解析不了
#   `archive.ubuntu.com` / `ports.ubuntu.com`，`apt-get update` 连续三次 exit 100，
#   把一条只做打包的流水线卡死（镜像本身没有任何编译动作）。
# ===========================================================================
FROM busybox:1.37.0 AS busybox
FROM alpine:3.20 AS certs

FROM ubuntu:24.04

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-field-api"
LABEL org.opencontainers.image.description="Compute-zone read API: evidence / atlas / metrics aggregation"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 根证书（编排里对 https 上游/浏览器入口都要用）+ 静态 busybox（compose 健康检查用）。
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=busybox /bin/busybox /bin/busybox

# uid 固定 10001：不建 passwd 条目也能跑，但建了排障时 `ps` 里能看到用户名。
RUN useradd -r -u 10001 -s /usr/sbin/nologin wist

COPY ${TARGETARCH}/wist-field-api /usr/local/bin/wist-field-api

# 配置与密钥由 stack 挂载到 /etc/wist-field-api。
ENV WIST_FIELD_CONFIG=/etc/wist-field-api/field-api.toml \
    WIST_FIELD_SEC_FILE=/etc/wist-field-api/.wist/sec-value.yml

USER 10001:10001
EXPOSE 8080

# 健康检查由编排（compose）定义；镜像里只提供 /bin/busybox。
ENTRYPOINT ["wist-field-api"]
