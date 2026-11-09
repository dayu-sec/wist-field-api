//! 证据读取 API 的自述（OpenAPI 3.1）。
//!
//! 浏览器能调的"证据读接口"就是 BFF 这几个：证据服务的 `/internal/*` 不在浏览器可达
//! 范围内（身份头由 BFF 从配置里带），所以清单写的是 **BFF 自己的路径** —— 页面上的
//! curl 示例可以照抄执行，只需要一把数据场令牌（`wcr_…`）。
//!
//! 与 atlas 的 `/api/openapi.json` 同一个用途：「接口可用性」页拿它渲染接口列表，
//! 页面不维护第二份清单。区别只在归属 —— atlas 的 spec 由 atlas 出，证据读接口的
//! 对外面就是 BFF，所以由 BFF 出。
//!
//! 这里只覆盖**读**：写端点属于数据面（`POST /internal/evidence`），浏览器不该碰。

use serde_json::{Value, json};

fn json_response(description: &str, schema: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": { "$ref": format!("#/components/schemas/{schema}") }
            }
        }
    })
}

fn error_response(description: &str) -> Value {
    json_response(description, "Error")
}

fn id_parameter() -> Value {
    json!({
        "name": "cmd_id",
        "in": "path",
        "required": true,
        "description": "调查命令 id（发起调查时拿到的那一个）。也接受列表行里的证据 id（`art_…`）——两套 id 指向同一行，证据服务先按证据 id 再按命令 id 找。",
        "schema": { "type": "string" }
    })
}

/// 证据读接口的完整 spec。
pub fn evidence() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "数据场 · 证据读取 API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "浏览器只跟 BFF 说话：令牌（`Authorization: Bearer wcr_…`）在这里验，\
                            到证据服务的身份（租户 / scope / 敏感度）由 BFF 从配置里带，\
                            页面不需要知道证据服务的地址。跨租户 / 无权限 / 过期一律是 404 —— \
                            BFF 不区分「不存在」和「不能看」。"
        },
        "security": [{ "bearerAuth": [] }],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "wcr_…"
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": { "type": "string", "description": "稳定错误码，页面按它分支。" },
                                "message": { "type": "string", "description": "一句人话；上游细节只进服务日志。" }
                            }
                        }
                    }
                },
                "EvidenceArtifact": {
                    "type": "object",
                    "description": "证据索引行（与证据服务的索引契约一致）。",
                    "properties": {
                        "artifact_id": { "type": "string" },
                        "tenant_id": { "type": "string", "description": "租户 = 客户：一个维度。" },
                        "customer_id": { "type": "string" },
                        "kind": { "type": "string" },
                        "subtype": { "type": ["string", "null"] },
                        "subject_type": { "type": "string" },
                        "subject_id": { "type": "string" },
                        "gateway_id": { "type": ["string", "null"] },
                        "agent_id": { "type": ["string", "null"] },
                        "command_id": { "type": ["string", "null"] },
                        "dedupe_key": { "type": "string" },
                        "schema_id": { "type": "string" },
                        "sensitivity": { "type": "string" },
                        "retention_class": { "type": "string" },
                        "bucket": { "type": "string" },
                        "object_key": { "type": "string" },
                        "size_bytes": { "type": "integer", "format": "int64" },
                        "sha256": { "type": "string" },
                        "verdict": { "type": "string" },
                        "marker_ids": { "type": "array", "items": { "type": "string" } },
                        "source_ref": { "type": ["string", "null"] },
                        "source_sha256": { "type": ["string", "null"] },
                        "durability": { "type": "string" },
                        "reported_at": { "type": "string", "format": "date-time" },
                        "stored_at": { "type": "string", "format": "date-time" },
                        "retention_until": { "type": "string", "format": "date-time" },
                        "legal_hold": { "type": "boolean" },
                        "state": { "type": "string" }
                    }
                },
                "EvidenceListPage": {
                    "type": "object",
                    "properties": {
                        "artifacts": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/EvidenceArtifact" }
                        },
                        "next_cursor": {
                            "type": ["string", "null"],
                            "description": "下一页游标；`null` = 到底了。原样回传给 `cursor`。"
                        }
                    }
                },
                "PresignResult": {
                    "type": "object",
                    "description": "单对象、短有效期的签名 URL。`objects.kind = file` 的部署没有这一条（501）。",
                    "properties": {
                        "artifact_id": { "type": "string" },
                        "url": { "type": "string", "format": "uri" },
                        "expires_in_seconds": { "type": "integer" },
                        "expires_at": { "type": "string", "format": "date-time" }
                    }
                },
                "EvidenceCapabilities": {
                    "type": "object",
                    "description": "证据服务的部署自述：页面据此选「打开正文」的通路。",
                    "properties": {
                        "objects_kind": {
                            "type": ["string", "null"],
                            "description": "对象后端：`file` / `s3`；探测不到（老服务不报）时为 `null`。"
                        },
                        "presign_supported": {
                            "type": "boolean",
                            "description": "`false`（本地文件存储）时正文只能走 BFF 代理读。"
                        }
                    }
                }
            }
        },
        "paths": {
            "/api/evidence": {
                "get": {
                    "summary": "列出可见的证据（按时间倒序）",
                    "description": "透传证据服务的索引查询。最常用的筛选是 `cmd_id`：发起调查的人手里只有命令 id。\
                                    租户由 BFF 的配置决定：URL 里带 `tenant` 会被丢掉。",
                    "tags": ["证据"],
                    "parameters": [
                        {
                            "name": "cmd_id",
                            "in": "query",
                            "required": false,
                            "description": "只看这次调查的产物（发起调查时拿到的命令 id）。",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "kind",
                            "in": "query",
                            "required": false,
                            "description": "证据类型（如 `investigation_report`）；不认识的值回 400。",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "subject_id",
                            "in": "query",
                            "required": false,
                            "description": "只看这个主体的证据（客户 / 资产）。",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "since",
                            "in": "query",
                            "required": false,
                            "description": "只看该时间之后（RFC 3339）。",
                            "schema": { "type": "string", "format": "date-time" }
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "required": false,
                            "description": "每页条数，缺省 50，超出范围按 1–200 夹紧。",
                            "schema": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 }
                        },
                        {
                            "name": "cursor",
                            "in": "query",
                            "required": false,
                            "description": "上一页返回的 `next_cursor`。",
                            "schema": { "type": "string" }
                        }
                    ],
                    "responses": {
                        "200": json_response("证据索引页", "EvidenceListPage"),
                        "400": error_response("参数不对（如未知 `kind`）"),
                        "401": error_response("令牌缺失 / 过期 / 被撤销"),
                        "502": error_response("证据服务不可用（`field_upstream_failed`）")
                    }
                }
            },
            "/api/evidence/capabilities": {
                "get": {
                    "summary": "证据服务自述：正文怎么读",
                    "description": "让后端自己说清楚对象后端是 `file` 还是 `s3`，页面不再先发一个必然 501 的签名请求。",
                    "tags": ["证据"],
                    "responses": {
                        "200": json_response("能力自述", "EvidenceCapabilities"),
                        "401": error_response("令牌缺失 / 过期 / 被撤销"),
                        "502": error_response("证据服务不可用（`field_upstream_failed`）")
                    }
                }
            },
            "/api/evidence/{cmd_id}": {
                "get": {
                    "summary": "读一条证据的索引行",
                    "description": "发起调查的人手里只有命令 id（`cmd_id`）：把它直接放路径里就能定位这次调查的产物。\
                                    内部的证据 id（`art_…`，列表行里给）同样可用。未知 / 跨租户 / 敏感度过高 / 已过期一律 404。",
                    "tags": ["证据"],
                    "parameters": [id_parameter()],
                    "responses": {
                        "200": json_response("证据索引行", "EvidenceArtifact"),
                        "401": error_response("令牌缺失 / 过期 / 被撤销"),
                        "404": error_response("不存在或不可见（`evidence_not_found`）"),
                        "502": error_response("证据服务不可用（`field_upstream_failed`）")
                    }
                }
            },
            "/api/evidence/{cmd_id}:presign": {
                "post": {
                    "summary": "换一个 60 秒、单对象的签名 URL",
                    "description": "路径里的 id 与详情读一致：调查命令 id（`cmd_id`）或内部的证据 id。\
                                    仅 `objects.kind = s3` 的部署支持；本地文件存储回 501，正文改走 `/content`。\
                                    请求体留空（有效期由服务端夹到 60s）。",
                    "tags": ["证据"],
                    "parameters": [id_parameter()],
                    "responses": {
                        "200": json_response("签名 URL", "PresignResult"),
                        "401": error_response("令牌缺失 / 过期 / 被撤销"),
                        "404": error_response("不存在或不可见（`evidence_not_found`）"),
                        "501": error_response("这个部署不签发签名 URL（`evidence_presign_unsupported`）"),
                        "502": error_response("证据服务不可用（`field_upstream_failed`）")
                    }
                }
            },
            "/api/evidence/{cmd_id}/content": {
                "get": {
                    "summary": "代理读正文",
                    "description": "路径里的 id 与详情读一致（命令 id 或证据 id）。\
                                    本地文件存储（`objects.kind = file`）没有签名 URL，这是唯一的读正文通路：\
                                    BFF 带自己的身份去证据服务取原文。响应带 `no-store` 与 `nosniff`。",
                    "tags": ["证据"],
                    "parameters": [id_parameter()],
                    "responses": {
                        "200": {
                            "description": "证据原文（JSON 文件）",
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object", "additionalProperties": true }
                                }
                            }
                        },
                        "401": error_response("令牌缺失 / 过期 / 被撤销"),
                        "404": error_response("不存在或不可见（`evidence_not_found`）"),
                        "502": error_response("证据服务不可用（`field_upstream_failed`）")
                    }
                }
            }
        }
    })
}
