"""载荷对象上传与数据库事务的协调（持久化提交状态机）。

协议（每个内容地址 sha 一把 Postgres 会话级咨询锁，串行化该 sha 上的
提交 / 迁移 / GC，杜绝悬空引用与误删）：

    阶段 1 begin   ：持锁 upsert event_payloads(status='uploading') 后提交、放锁；
                     行是“对象即将上传”的持久化意图，先于对象存在也安全。
    阶段 2 upload  ：按内容地址幂等上传不可变对象（已存在即复核复用）。
    阶段 3 commit  ：再次持锁——头校验对象存在（缺失则用本进程持有的字节
                     重传），单事务把状态推进 committed 并插入事件与投递，
                     随后放锁。

崩溃分析（任一步失败 / 进程被杀 / 重启）：

- 阶段 1 后崩溃：留下 uploading 行；下次同摘要提交幂等接管；宽限期后
  仍无引用则由 GC（`app/objadmin.py gc`）连同可能已上传的对象一起回收。
- 阶段 2 后崩溃：对象已在桶中但状态仍是 uploading（或事件未插入）；
  重启后重跑协议：head 命中即复用，阶段 3 照常完成；若始终无人提交，
  该对象以“孤儿/废弃上传”身份在宽限期后被 GC 回收。
- 阶段 3 失败：事务整体回滚，对外不可见任何半成品事件/投递；对象保持
  不可变且可被未来提交复用。
- 重复提交：(source, event_id) 唯一冲突，不新增任何投递（幂等不变）。

因此对外**永远只可能**看到“事件引用已 committed 且对象确实存在”的状态，
不会出现可见的半成品、悬空引用或重复投递。
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

import asyncpg

from app import repository as repo
from app.object_store import ObjectStore, ObjectStoreError
from app.payload_object import content_address, object_key

log = logging.getLogger("webhook.payload")

DUAL_WRITE_META_KEY = "payload_jsonb_dual_write"
# 滚动升级期默认双写 JSONB：旧版本 worker 仍可能从 JSONB 双读；
# 全量升级 + 迁移完成后用 objadmin dual-write off 切换。
DUAL_WRITE_DEFAULT = True


@asynccontextmanager
async def _sha_advisory_lock(conn: asyncpg.Connection, sha: str):
    """持有按内容地址派生的会话级咨询锁（提交/迁移/GC 三方互斥）。

    用会话锁而非事务锁：阶段 3 需要在“头校验（网络）→ 数据库提交”之间
    持续互斥。连接释放回池前一定解锁；进程崩溃时 Postgres 自动释放。
    """
    key = repo.advisory_key_for_sha(sha)
    await conn.execute("SELECT pg_advisory_lock($1)", key)
    try:
        yield
    finally:
        # 尽力释放；连接异常归还池时服务端也会随会话结束自动释放。
        try:
            await conn.execute("SELECT pg_advisory_unlock($1)", key)
        except Exception:  # noqa: BLE001 - 解锁失败只记录，避免掩盖主异常
            log.warning("咨询锁释放失败 sha=%s（会话结束后将自动释放）", sha[:12])


async def submit_event(
    pool,
    store: ObjectStore,
    source: str,
    event_id: str,
    payload: dict[str, Any],
) -> tuple[asyncpg.Record, bool]:
    """执行完整的三阶段提交；返回 (event 行, 是否重复提交)。"""
    sha, body = content_address(payload)
    key = object_key(sha)

    # 阶段 1：持久化上传意图（持锁，与 GC 的孤儿登记互斥）。
    async with pool.acquire() as conn:
        async with _sha_advisory_lock(conn, sha):
            async with conn.transaction():
                await repo.begin_event_payload(conn, sha, key, len(body))

    # 阶段 2：上传不可变对象（数据库事务之外；幂等、可安全重试）。
    await store.put_payload_if_absent(key, body, sha)

    # 阶段 3：持锁确认对象存在后原子提交状态机 + 事件 + 投递。
    async with pool.acquire() as conn:
        async with _sha_advisory_lock(conn, sha):
            # GC 可能已在宽限期后回收了废弃 uploading 行（24h 无引用）；
            # 持锁下重建并保证对象在位即可继续。
            meta = await repo.get_payload_status(conn, sha)
            if meta is None:
                async with conn.transaction():
                    await repo.begin_event_payload(conn, sha, key, len(body))
            if meta is None or meta["status"] != "committed":
                # 头校验；万一对象在阶段 2 后被外部删除则用本进程字节重传。
                if await _object_missing(store, key):
                    await store.put_payload_if_absent(key, body, sha)
            dual_write = await repo.get_meta_flag(
                conn, DUAL_WRITE_META_KEY, DUAL_WRITE_DEFAULT
            )
            row, duplicate = await repo.commit_event(
                conn,
                source=source,
                event_id=event_id,
                payload=payload,
                sha=sha,
                dual_write_jsonb=dual_write,
            )
    if duplicate:
        log.info("事件幂等命中 source=%s event_id=%s", source, event_id)
    return row, duplicate


async def _object_missing(store: ObjectStore, key: str) -> bool:
    import asyncio

    from app.object_store import ObjectNotFound

    try:
        await asyncio.to_thread(store.head_object_sync, key)
        return False
    except ObjectNotFound:
        return True


async def resolve_event_payload(
    pool, store: ObjectStore | None, row: asyncpg.Record
) -> dict[str, Any]:
    """双读解析事件载荷：优先 JSONB 副本（迁移期/双写期），否则读对象存储。

    读取对象后强制复核 SHA-256（与事件引用的内容地址逐字节比对），
    摘要不符即拒绝（对象被破坏/替换），抛 PayloadUnavailable。
    """
    if row["payload"] is not None:
        return dict(row["payload"])
    sha = row["payload_sha256"]
    if not sha or store is None:
        raise PayloadUnavailable(
            "payload_not_migrated", "事件载荷尚未迁移到对象存储且无 JSONB 副本"
        )
    return await fetch_and_verify(store, sha, object_key(sha))


async def fetch_and_verify(
    store: ObjectStore, sha: str, key: str
) -> dict[str, Any]:
    """取对象字节 → 复核 SHA-256 → 解析 JSON。任何不符抛 PayloadUnavailable。"""
    import json

    from app.payload_object import sha256_hex

    try:
        body = await store.get_object(key)
    except ObjectStoreError as exc:
        raise PayloadUnavailable(
            exc.code if isinstance(exc.code, str) else "object_store_error",
            f"读取载荷对象失败: {exc}",
        ) from exc
    actual = sha256_hex(body)
    if actual != sha:
        raise PayloadUnavailable(
            "payload_digest_mismatch",
            f"载荷对象摘要复核失败：期望 {sha[:12]}… 实际 {actual[:12]}…",
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadUnavailable(
            "payload_decode_failed", "载荷对象不是合法 UTF-8 JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise PayloadUnavailable(
            "payload_shape_invalid", "载荷对象顶层必须是 JSON 对象"
        )
    return payload


class PayloadUnavailable(Exception):
    """Worker/读取路径无法取得可信载荷（对象缺失、摘要不符、存储不可用）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
