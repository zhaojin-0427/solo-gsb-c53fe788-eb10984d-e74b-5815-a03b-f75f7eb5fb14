"""事件载荷的规范化与内容寻址。

载荷对象的唯一身份是其**规范化 JSON**（键排序、无空白、不转义非 ASCII，
与投递签名原文 `security.compact_json` 完全一致）的 SHA-256 摘要：

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    sha256    = hashlib.sha256(canonical).hexdigest()

- 相同语义的载荷（键顺序不同、空白不同）归一化后摘要相同，天然去重；
- 规范化字节同时就是 Worker 投递的 HTTP 请求体与 HMAC 签名原文，因此
  “摘要一致”即“投递字节与入库载荷逐字节一致”；
- 对象不可变：S3 中同一 key 永远写入同一字节，任何并发提交只能引用、
  不能改变对象内容。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# 与 app.security.compact_json 保持一致：签名、去重、存储三处必须逐字节相同。
def canonical_payload_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_address(payload: Any) -> tuple[str, bytes]:
    """返回 (sha256 hex, 规范化字节)。"""
    body = canonical_payload_bytes(payload)
    return sha256_hex(body), body


# S3 对象 key：按摘要前两位分目录，避免单目录下对象过多。
def object_key(sha: str) -> str:
    return f"payloads/{sha[:2]}/{sha}"


# 桶内对象的元数据与内容类型（写入时固定；不可变对象不会再被改写）。
OBJECT_CONTENT_TYPE = "application/json"
META_SHA256 = "sha256"
META_KIND = "kind"
META_KIND_VALUE = "event-payload"
