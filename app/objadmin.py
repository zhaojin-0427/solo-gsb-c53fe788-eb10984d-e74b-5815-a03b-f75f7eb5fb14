"""载荷对象存储管理命令：在线迁移、双写切换、JSONB 副本回收、垃圾回收。

用法（容器内）：

    python -m app.objadmin status                 # 对象存储/迁移/双写/GC 总览
    python -m app.objadmin migrate [--batch-size N] [--stop-after-empty]
                                                  # 旧 JSONB 事件 -> 对象存储
                                                  # （幂等、断点续跑、可并发）
    python -m app.objadmin dual-write on|off      # 切换迁移期 JSONB 双写开关
    python -m app.objadmin drop-jsonb [--batch-size N]
                                                  # 双读切换后释放 JSONB 副本
                                                  # （幂等、断点续跑）
    python -m app.objadmin gc [--grace-seconds S] [--batch-size N] [--scan]
                                                  # 垃圾回收：引用复核 + 宽限期
                                                  # + 两阶段删除

安全模型（为什么不会误删并发提交 / 重放正在引用的对象）：

- 每个内容地址 sha 一把 Postgres 会话级咨询锁，提交协议
  （app/payload_service.py）、迁移与 GC 在该 sha 上完全串行；
- GC 只删除“桶中存在但数据库目录无行（orphan_object）”或“宽限期后仍为
  uploading 且无任何事件引用（abandoned_upload）”的对象；
- 删除发生在登记（阶段一）+ 宽限期之后的阶段二，删除前在同事务内再次
  复核目录与 events 引用；
- 死信重放只新建投递、不新建事件，引用的仍是原事件的同一对象，因此
  “events 是否引用该 sha”是充分的引用复核。
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone

from app import payload_service, repository as repo
from app.config import settings
from app.db import close_pool, init_db
from app.object_store import ObjectStoreError, init_object_store
from app.payload_object import object_key, sha256_hex

log = logging.getLogger("webhook.objadmin")


# -- status -----------------------------------------------------------------------

async def _status(close: bool = True) -> int:
    pool = await init_db()
    store = await init_object_store()
    try:
        async with pool.acquire() as conn:
            dual = await repo.get_meta_flag(
                conn, payload_service.DUAL_WRITE_META_KEY,
                payload_service.DUAL_WRITE_DEFAULT,
            )
            legacy = await repo.count_legacy_payload_events(conn)
            dual_copy = await repo.count_dual_copy_events(conn)
            committed = await repo.count_committed_payloads(conn)
            uploading = await repo.count_uploading_payloads(conn)
            claims = await repo.count_gc_claims(conn)
            migrations = await repo.list_payload_migrations(conn)
    finally:
        if close:
            await close_pool()

    print(
        f"对象存储：endpoint={settings.s3_endpoint_url or '(aws default)'} "
        f"bucket={settings.s3_bucket}"
    )
    print(f"JSONB 双写开关 payload_jsonb_dual_write：{'on' if dual else 'off'}")
    print(f"已提交对象（committed）：{committed}")
    print(f"上传意图未决（uploading）：{uploading}")
    print(f"旧 JSONB 事件待迁移（无内容地址）：{legacy}")
    print(f"仍保留 JSONB 副本的事件（双写期/待回收）：{dual_copy}")
    print(
        "GC 凭证：registered={registered} delete_due={delete_due} "
        "deleted={deleted} cancelled={cancelled}".format(**claims)
    )
    if migrations:
        print("载荷迁移运行：")
        for m in migrations:
            print(
                f"  #{m['id']} [{m['status']}] processed={m['processed_count']} "
                f"last_event_id={m['last_event_id']}"
                + (f" error={m['last_error']}" if m["last_error"] else "")
            )
    else:
        print("载荷迁移运行：无")
    print(f"GC 宽限期配置：{settings.gc_grace_seconds} 秒"
          f"（PAYLOAD_GC_GRACE_SECONDS 可覆盖）")
    return 0


# -- migrate（JSONB -> 对象存储）---------------------------------------------------

async def _migrate(batch_size: int, close: bool = True) -> int:
    pool = await init_db()
    store = await init_object_store()
    total = 0
    try:
        async with pool.acquire() as conn:
            run = await repo.start_or_adopt_payload_migration(conn)
        migration_id = run["id"]
        if run["status"] != "running" or run["processed_count"]:
            print(
                f"{'接续' if run['status'] == 'failed' else '进行中'}"
                f"载荷迁移运行 #{migration_id}（已完成 {run['processed_count']} 条），"
                "断点续跑"
            )
        last_id = int(run["last_event_id"])
        try:
            while True:
                # 每批：锁行 -> 规范化上传（去重）-> 单事务置 committed + 回填。
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        rows = await repo.fetch_legacy_payload_batch(
                            conn, last_id, batch_size
                        )
                        if not rows:
                            break
                        for row in rows:
                            # JSONB -> 规范化字节 -> 内容地址（与提交路径完全一致）
                            payload = dict(row["payload"])
                            from app.payload_object import canonical_payload_bytes

                            body = canonical_payload_bytes(payload)
                            sha = sha256_hex(body)
                            key = object_key(sha)
                            await store.put_payload_if_absent(key, body, sha)
                            await repo.ensure_payload_committed(
                                conn, sha, key, len(body)
                            )
                            await repo.attach_event_payload(conn, row["id"], sha)
                        batch_last = max(r["id"] for r in rows)
                        await repo.update_payload_migration_progress(
                            conn, migration_id, len(rows), batch_last
                        )
                        last_id = max(last_id, batch_last)
                total += len(rows)
                log.info("已迁移 %d 个事件载荷（累计 %d）", len(rows), total)
                if len(rows) < batch_size:
                    break
        except ObjectStoreError as exc:
            async with pool.acquire() as conn:
                await repo.finish_payload_migration(conn, "failed", str(exc))
            print(f"迁移失败（对象存储恢复后重跑即断点续跑）: {exc}",
                  file=sys.stderr)
            return 1
        async with pool.acquire() as conn:
            await repo.finish_payload_migration(conn, "completed")
            remaining = await repo.count_legacy_payload_events(conn)
        print(f"迁移完成：共回填 {total} 个事件载荷；剩余旧事件 {remaining}")
        if remaining:
            print("提示：仍有旧事件（可能迁移期间有旧版本进程写入），重跑本命令即可")
        return 0
    finally:
        if close:
            await close_pool()


# -- dual-write 开关 ---------------------------------------------------------------

async def _dual_write(enable: bool, close: bool = True) -> int:
    pool = await init_db()
    try:
        async with pool.acquire() as conn:
            await repo.set_meta_flag(
                conn, payload_service.DUAL_WRITE_META_KEY, enable
            )
            current = await repo.get_meta_flag(
                conn, payload_service.DUAL_WRITE_META_KEY,
                payload_service.DUAL_WRITE_DEFAULT,
            )
        print(f"JSONB 双写已切换为：{'on' if current else 'off'}")
        if not current:
            print(
                "此后新事件只把载荷写入对象存储。请确认所有 api/worker 均已升级"
                "（旧版本无法读取无 JSONB 副本的事件），并确认迁移已完成后再执行"
                " drop-jsonb 释放旧副本。"
            )
        return 0
    finally:
        if close:
            await close_pool()


# -- drop-jsonb（释放双写副本）-----------------------------------------------------

async def _drop_jsonb(batch_size: int, close: bool = True) -> int:
    """双读切换完成后，逐批把已回填内容地址事件的 JSONB 副本置空。

    幂等、断点续跑：只处理 payload_sha256 IS NOT NULL AND payload IS NOT NULL。
    """
    pool = await init_db()
    total = 0
    try:
        async with pool.acquire() as conn:
            dual = await repo.get_meta_flag(
                conn, payload_service.DUAL_WRITE_META_KEY,
                payload_service.DUAL_WRITE_DEFAULT,
            )
        if dual:
            print(
                "当前 JSONB 双写仍为 on：新事件还在产生副本。建议先执行 "
                "`objadmin dual-write off` 并等待在途提交结束，再运行本命令"
                "（仍会继续清理历史副本）。",
                file=sys.stderr,
            )
        while True:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    rows = await conn.fetch(
                        """
                        SELECT id FROM events
                        WHERE payload_sha256 IS NOT NULL AND payload IS NOT NULL
                        ORDER BY id
                        LIMIT $1
                        FOR UPDATE SKIP LOCKED
                        """,
                        batch_size,
                    )
                    for row in rows:
                        await repo.clear_event_jsonb(conn, row["id"])
            if not rows:
                break
            total += len(rows)
            log.info("已释放 %d 个事件的 JSONB 副本（累计 %d）", len(rows), total)
            if len(rows) < batch_size:
                break
        async with pool.acquire() as conn:
            remaining = await repo.count_dual_copy_events(conn)
        print(f"JSONB 副本回收完成：本次释放 {total}；剩余双副本事件 {remaining}")
        return 0
    finally:
        if close:
            await close_pool()


# -- gc（垃圾回收）-----------------------------------------------------------------

async def _gc(grace_seconds: int, batch_size: int, do_scan: bool, close: bool = True) -> int:
    pool = await init_db()
    store = await init_object_store()
    now = datetime.now(timezone.utc)
    stale_before = now - timedelta(seconds=grace_seconds)
    summary = {"registered": 0, "deleted": 0, "skipped": 0}
    try:
        # ---- 阶段一扫描：登记候选（不在本进程删除对象，只登记 + 宽限期）----

        # 1) abandoned_upload：宽限期后仍 uploading 且无事件引用的目录行。
        async with pool.acquire() as conn:
            stale_rows = await repo.fetch_abandoned_uploads(
                conn, stale_before, batch_size
            )
        for row in stale_rows:
            sha = row["sha256"]
            async with pool.acquire() as conn:
                async with payload_service._sha_advisory_lock(conn, sha):
                    async with conn.transaction():
                        # 登记删除凭证（reason=abandoned_upload）。登记与目录行
                        # 删除在同一事务；持锁期间没有提交能插入同 sha 的引用。
                        # 已终结（deleted/cancelled）的旧凭证需要复活为
                        # registered（同一 sha 可能再次出现废弃上传）。
                        due = now + timedelta(seconds=grace_seconds)
                        await conn.execute(
                            """
                            INSERT INTO payload_gc_claims
                                (sha256, object_key, reason, status,
                                 delete_due_at, finished_at, last_error)
                            VALUES ($1, $2, 'abandoned_upload', 'registered',
                                    $3, NULL, NULL)
                            ON CONFLICT (sha256) DO UPDATE
                                SET object_key = EXCLUDED.object_key,
                                    reason = EXCLUDED.reason,
                                    status = 'registered',
                                    delete_due_at = EXCLUDED.delete_due_at,
                                    finished_at = NULL,
                                    last_error = NULL
                            """,
                            sha, row["object_key"], due,
                        )
                        await repo.delete_payload_row(conn, sha)
            summary["registered"] += 1

        # 2) orphan_object：列举桶内对象，目录中完全没有、且无 GC 凭证的。
        if do_scan:
            keys = await store.list_object_keys(prefix="payloads/", limit=50_000)
            for key in keys:
                sha = key.rsplit("/", 1)[-1]
                if len(sha) != 64:
                    continue
                async with pool.acquire() as conn:
                    async with payload_service._sha_advisory_lock(conn, sha):
                        async with conn.transaction():
                            status = await repo.register_orphan_claim(
                                conn,
                                sha,
                                key,
                                "orphan_object",
                                now + timedelta(seconds=grace_seconds),
                            )
                if status == "registered":
                    summary["registered"] += 1

        # ---- 阶段二删除：宽限期到期的凭证，持锁做最终引用复核后删对象 ----
        async with pool.acquire() as conn:
            due_claims = await repo.fetch_due_claims(conn, now, batch_size)
        for claim in due_claims:
            sha = claim["sha256"]
            async with pool.acquire() as conn:
                async with payload_service._sha_advisory_lock(conn, sha):
                    async with conn.transaction():
                        removable = await repo.recheck_claim_removable(conn, sha)
                        if not removable:
                            await repo.mark_claim_cancelled(conn, sha)
                            summary["skipped"] += 1
                            continue
                    # 事务已提交（复核结论已持久化在同锁视图下）；持锁删除
                    # S3 对象——提交协议阶段 1/3 必须先拿同一把锁，因此删除
                    # 与“引用该对象”不可能并发交错。
                    try:
                        await store.delete_object(claim["object_key"])
                    except ObjectStoreError as exc:
                        async with conn.transaction():
                            await repo.mark_claim_error(conn, sha, str(exc))
                        summary["skipped"] += 1
                        log.warning("删除对象失败 sha=%s: %s", sha[:12], exc)
                        continue
                    async with conn.transaction():
                        await repo.mark_claim_deleted(conn, sha)
                    summary["deleted"] += 1

        print(
            "GC 完成：新登记 {registered}，删除 {deleted}，"
            "跳过（宽限期未满/重新被引用）{skipped}".format(**summary)
        )
        if not do_scan:
            print("提示：未加 --scan，本次只回收数据库已知的废弃上传意图；"
                  "定期运行 `gc --scan` 可发现桶内无目录孤儿对象。")
        return 0
    finally:
        if close:
            await close_pool()


# -- 入口 --------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(prog="objadmin", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="查看对象存储/迁移/双写/GC 状态")

    p_migrate = sub.add_parser(
        "migrate", help="把旧 JSONB 事件载荷批量迁移到对象存储（断点续跑）"
    )
    p_migrate.add_argument("--batch-size", type=int, default=200)

    p_dual = sub.add_parser("dual-write", help="查看/切换 JSONB 双写开关")
    p_dual.add_argument("mode", choices=["on", "off"])

    p_drop = sub.add_parser(
        "drop-jsonb", help="双读切换后释放事件的 JSONB 副本（断点续跑）"
    )
    p_drop.add_argument("--batch-size", type=int, default=500)

    p_gc = sub.add_parser("gc", help="垃圾回收（引用复核 + 宽限期 + 两阶段删除）")
    p_gc.add_argument(
        "--grace-seconds", type=int, default=settings.gc_grace_seconds,
        help="宽限期秒数（默认取 PAYLOAD_GC_GRACE_SECONDS，通常 24h）",
    )
    p_gc.add_argument("--batch-size", type=int, default=500)
    p_gc.add_argument(
        "--scan", action="store_true",
        help="列举桶内对象，登记数据库目录中不存在的孤儿对象",
    )

    args = parser.parse_args()
    if args.command == "status":
        code = asyncio.run(_status())
    elif args.command == "migrate":
        code = asyncio.run(_migrate(args.batch_size))
    elif args.command == "dual-write":
        code = asyncio.run(_dual_write(args.mode == "on"))
    elif args.command == "drop-jsonb":
        code = asyncio.run(_drop_jsonb(args.batch_size))
    elif args.command == "gc":
        code = asyncio.run(_gc(args.grace_seconds, args.batch_size, args.scan))
    else:  # pragma: no cover
        parser.error("未知命令")
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
