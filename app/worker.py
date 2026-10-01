"""投递 Worker 进程。

并发模型：单进程内每轮认领一个队首任务并同步投递，可通过 docker compose
`--scale worker=N` 水平扩展；数据库行锁 + SKIP LOCKED 保证任务不被重复认领。
租约（LEASE_SECONDS）到期后，其他 Worker 可接管卡死/宕机的任务，
回写用 lease_token 栅栏丢弃过期结果（可能产生一次重复投递，这是 at-least-once
语义的正常表现）。
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from app import repository as repo
from app import security
from app.config import settings
from app.db import init_db, close_pool
from app.egress_policy import EgressPolicyError, policy_from_env
from app.egress_transport import PolicyAsyncTransport
from app.envelope import SecretCryptoError, resolve_secret
from app.keyring import get_keyring
from app.object_store import ObjectStoreError, get_object_store
from app.payload_service import (
    PayloadUnavailable,
    fetch_and_verify,
)
from app.payload_object import object_key

log = logging.getLogger("webhook.worker")

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

RESPONSE_EXCERPT_LIMIT = 2048


def compute_backoff(
    attempt_number: int, base_seconds: float, cap_seconds: float
) -> datetime:
    """第 attempt_number 次失败后，下次可投递时间（指数退避，封顶）。

    base/cap 取自该投递钉住的配置版本：旧投递即使在配置发布后重试，
    也继续沿用其创建时版本的退避参数。
    """
    delay = min(cap_seconds, base_seconds * (2 ** (attempt_number - 1)))
    return datetime.now(timezone.utc) + timedelta(seconds=delay)


async def deliver_once(
    client: httpx.AsyncClient, context: dict, body: bytes
) -> tuple[str, int | None, str | None, str | None, bool]:
    """执行一次 HTTP 投递。

    body 是已经过 SHA-256 复核的规范化载荷字节（签名原文即 HTTP 请求体）。
    返回 (outcome, http_status, response_excerpt, error_message, succeeded)。
    """
    timestamp = security.now_timestamp()
    signature = security.build_signature_header_for_body(
        context["secret"], timestamp, body
    )
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
        "X-Webhook-Event": context["source"],
        "X-Webhook-Event-Id": context["event_id"],
        "X-Webhook-Delivery-Id": str(context["delivery_id"]),
        "X-Webhook-Attempt": str(context["attempt_number"]),
        # 本次投递实际使用的配置版本（钉在投递记录上，重试/接管不变）
        "X-Webhook-Config-Revision": str(context["config_revision"]),
        "User-Agent": "reliable-webhook/1.0",
    }
    try:
        response = await client.post(
            context["target_url"], content=body, headers=headers
        )
    except EgressPolicyError as exc:
        # 出站安全策略拒绝（含重定向后任意一跳命中阻止类别）：
        # 记录为可查询的 security_blocked，并与普通失败一样参与重试/退避/死信结算。
        log.warning(
            "投递 id=%s 目标被出站安全策略拒绝（%s）: %s",
            context["delivery_id"],
            exc.code,
            exc.message,
        )
        return "security_blocked", None, None, f"安全策略拒绝[{exc.code}]: {exc.message}", False
    except httpx.TimeoutException as exc:
        return "timeout", None, None, f"请求超时: {exc}", False
    except httpx.HTTPError as exc:
        return "network_error", None, None, f"网络错误: {exc}", False

    excerpt = response.text[:RESPONSE_EXCERPT_LIMIT]
    if 200 <= response.status_code < 300:
        return "success", response.status_code, excerpt, None, True
    return (
        "http_error",
        response.status_code,
        excerpt,
        f"目标返回 HTTP {response.status_code}",
        False,
    )


async def handle_one(pool, client: httpx.AsyncClient) -> bool:
    """认领并处理一个任务；返回本轮是否处理了任务。"""
    async with pool.acquire() as conn:
        claim = await repo.claim_delivery(conn, WORKER_ID)
    if claim is None:
        return False

    delivery = claim["delivery"]
    delivery_id = delivery["id"]
    lease_token = claim["lease_token"]
    log.info(
        "worker=%s 认领投递 id=%s event=%s attempt(即将)=%s",
        WORKER_ID,
        delivery_id,
        delivery["event_id_fk"],
        delivery["attempts_made"] + 1,
    )

    async with pool.acquire() as conn:
        context_row = await repo.load_delivery_context(conn, delivery_id)
    if context_row is None:
        return True
    context = dict(context_row)
    context["attempt_number"] = delivery["attempts_made"] + 1
    log.info(
        "worker=%s 认领投递 id=%s event=%s revision=%s attempt(即将)=%s",
        WORKER_ID,
        delivery_id,
        delivery["event_id_fk"],
        context.get("config_revision"),
        context["attempt_number"],
    )

    # 取载荷并在签名前复核摘要：
    # - 新路径：events.payload_sha256 引用不可变对象，从对象存储取字节并
    #   强制 SHA-256 复核，摘要不符/对象缺失/存储不可用一律拒绝投递，
    #   记 payload_error（与普通失败一样退避/重试/死信，对象恢复后自动恢复）；
    # - 迁移期双读兜底：未回填内容地址的旧事件回退 JSONB 副本，规范化后投递
    #   （字节与签名原文本就一致），迁移完成后该分支不再命中。
    sha = context.get("payload_sha256")
    store = get_object_store()
    try:
        if sha:
            payload = await fetch_and_verify(
                store, sha, context["object_key"] or object_key(sha)
            )
        else:
            legacy = context.get("legacy_payload")
            if legacy is None:
                raise PayloadUnavailable(
                    "payload_not_migrated",
                    "事件既无内容地址引用也无 JSONB 副本，无法投递",
                )
            payload = dict(legacy)
        body = security.compact_json(payload).encode("utf-8")
    except (PayloadUnavailable, ObjectStoreError) as exc:
        code = getattr(exc, "code", "object_store_error")
        message = getattr(exc, "message", str(exc))
        log.warning("投递 id=%s 载荷不可用[%s]: %s", delivery_id, code, message)
        outcome, http_status, excerpt, error_message, succeeded = (
            "payload_error",
            None,
            None,
            f"载荷校验失败[{code}]: {message}",
            False,
        )
        # 载荷不可用无需解密密钥，直接走结算。
        return await _settle(
            pool,
            claim,
            delivery_id,
            context,
            outcome,
            http_status,
            excerpt,
            error_message,
            succeeded,
        )

    # 仅在签名前解密订阅密钥（信封格式解包 DEK 后解密；旧明文格式直接回退）。
    # 未知 key_id / 认证失败 / 未配置密钥环：拒绝投递并记录可查询的 crypto_error，
    # 与普通失败一样参与退避/重试/死信结算（修复密钥环后可自动恢复）。
    try:
        context["secret"] = resolve_secret(context, get_keyring())
    except SecretCryptoError as exc:
        log.warning(
            "投递 id=%s 被拒绝：密钥不可用[%s] key_id=%s",
            delivery_id,
            exc.code,
            context.get("secret_key_id"),
        )
        outcome, http_status, excerpt, error_message, succeeded = (
            "crypto_error",
            None,
            None,
            f"密钥解密失败[{exc.code}]: {exc.message}",
            False,
        )
    else:
        outcome, http_status, excerpt, error_message, succeeded = await deliver_once(
            client, context, body
        )

    return await _settle(
        pool,
        claim,
        delivery_id,
        context,
        outcome,
        http_status,
        excerpt,
        error_message,
        succeeded,
    )


async def _settle(
    pool,
    claim: dict,
    delivery_id: int,
    context: dict,
    outcome: str,
    http_status: int | None,
    excerpt: str | None,
    error_message: str | None,
    succeeded: bool,
) -> bool:
    """租约栅栏下记录尝试并结算；返回本轮是否处理了任务（恒为 True）。"""
    lease_token = claim["lease_token"]
    # 租约栅栏：记录尝试与结算都校验 leased_by == lease_token，
    # 若任务已因租约超时被接管，本次结果作废，避免覆盖新 Worker 的状态。
    async with pool.acquire() as conn:
        attempt_number = await repo.record_attempt(
            conn,
            delivery_id=delivery_id,
            lease_token=lease_token,
            worker_id=WORKER_ID,
            outcome=outcome,
            http_status=http_status,
            response_excerpt=excerpt,
            error_message=error_message,
            leased_at=claim["leased_at"],
            lease_expires_at=claim["lease_expires_at"],
        )
        if attempt_number is None:
            log.warning(
                "投递 id=%s 的租约已被接管，本次尝试结果丢弃（outcome=%s）",
                delivery_id,
                outcome,
            )
            return True

        not_before = (
            None
            if succeeded
            else compute_backoff(
                attempt_number,
                float(context["backoff_base_seconds"]),
                float(context["backoff_cap_seconds"]),
            )
        )
        new_status = await repo.settle_delivery(
            conn,
            delivery_id=delivery_id,
            lease_token=lease_token,
            succeeded=succeeded,
            not_before=not_before,
            max_attempts=int(context["max_attempts"]),
        )

    if new_status == "succeeded":
        log.info("投递 id=%s 成功（第 %s 次尝试）", delivery_id, attempt_number)
    elif new_status == "dead_lettered":
        log.error(
            "投递 id=%s 已达 %s 次尝试，进入死信",
            delivery_id,
            context["max_attempts"],
        )
    else:
        log.info(
            "投递 id=%s 第 %s 次失败（%s），退避后重试",
            delivery_id,
            attempt_number,
            outcome,
        )
    return True


async def run() -> None:
    log.info("Worker 启动 id=%s", WORKER_ID)
    pool = await init_db()
    # 对象存储：确保桶存在（等待 MinIO/S3 就绪）；不可用则启动失败，
    # 避免 Worker 把所有任务都结算成 payload_error。
    from app.object_store import init_object_store

    await init_object_store()
    # 启动时加载本地密钥环：配置非法直接退出；未配置则明文旧记录可投递、
    # 已加密记录以 crypto_error 结算（可查询），修复配置后自动恢复。
    get_keyring()
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    policy = policy_from_env(settings.allowed_hosts, settings.allowed_cidrs)
    # follow_redirects=False：重定向由 PolicyAsyncTransport 逐跳重新执行
    # 同一出站策略，不会因 3xx 自动越过策略（含固定地址防 DNS 重绑定）。
    transport = PolicyAsyncTransport(policy, max_redirects=settings.max_redirects)
    async with httpx.AsyncClient(
        timeout=settings.http_timeout_seconds,
        follow_redirects=False,
        transport=transport,
        limits=httpx.Limits(max_connections=20),
    ) as client:
        try:
            while not stop.is_set():
                try:
                    handled = await handle_one(pool, client)
                except Exception:  # noqa: BLE001 - Worker 主循环不能因单任务退出
                    log.exception("处理投递时发生未预期错误")
                    handled = False
                if not handled:
                    try:
                        await asyncio.wait_for(
                            stop.wait(), timeout=settings.worker_poll_seconds
                        )
                    except asyncio.TimeoutError:
                        pass
        finally:
            await close_pool()
    log.info("Worker 停止 id=%s", WORKER_ID)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
