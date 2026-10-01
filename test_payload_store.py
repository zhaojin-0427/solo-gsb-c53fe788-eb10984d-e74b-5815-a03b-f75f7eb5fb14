"""载荷对象存储重构的集成验证（便携 Postgres + moto S3 模拟）。

覆盖：
1. 提交状态机三阶段：uploading 行 -> 对象 -> committed 事件+投递；幂等去重
2. 重复提交不新增投递；相同内容（键序不同）复用同一对象
3. 阶段 1/2 崩溃恢复：uploading 残留行与孤儿对象可被接管/GC
4. Worker 取载荷复核 SHA-256；对象损坏 -> payload_error 失败结算
5. 在线迁移：旧 JSONB 事件断点续跑回填，期间双读可投递
6. 双写切换 + drop-jsonb 后纯对象读取
7. GC：引用复核 + 宽限期 + 两阶段删除，不删被引用对象
8. 提交/GC 并发竞态（咨询锁串行）
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "")
os.environ["S3_ENDPOINT_URL"] = "http://127.0.0.1:5000"
os.environ["S3_ACCESS_KEY_ID"] = "test"
os.environ["S3_SECRET_ACCESS_KEY"] = "test"
os.environ["S3_BUCKET"] = "test-payloads"
os.environ["PAYLOAD_GC_GRACE_SECONDS"] = "0"
os.environ["WEBHOOK_KEYRING_JSON"] = (
    '{"active_key_id":"k1","keys":{"k1":"'
    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" + '"}}'
)

import pgserver  # noqa: E402

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import payload_service, repository as repo  # noqa: E402
from app.object_store import (  # noqa: E402
    get_object_store,
    reset_object_store_cache,
)
from app.payload_object import content_address, object_key  # noqa: E402
import app.db as dbmod  # noqa: E402

PASSED = []
FAILED = []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print(("  ok  " if cond else "FAIL  ") + name + (f"  {detail}" if detail and not cond else ""))


async def main():
    import tempfile

    pg_dir = Path(tempfile.mkdtemp(prefix="pg-payload-"))
    pg = pgserver.get_server(str(pg_dir), cleanup_mode="delete")
    os.environ["DATABASE_URL"] = pg.get_uri()
    # 重建连接池（settings 在导入时已固定）
    dbmod._pool = None
    import app.config as cfg
    cfg.settings.__dict__  # frozen dataclass：直接改模块单例属性
    object.__setattr__(cfg.settings, "database_url", pg.get_uri())

    reset_object_store_cache()
    pool = await dbmod.init_db()
    store = get_object_store()
    await store.ensure_bucket()

    # 清桶（重复运行）
    for k in await store.list_object_keys(prefix="payloads/", limit=10000):
        await store.delete_object(k)

    # -- 准备一个订阅（revision 1） ------------------------------------------
    from app.keyring import get_keyring

    keyring = get_keyring()
    async with pool.acquire() as conn:
        sub = await repo.create_subscription(
            conn, "orders", "http://example.invalid/hook", "dev-signing-secret",
            keyring=keyring, max_attempts=6,
            backoff_base_seconds=1.0, backoff_cap_seconds=8.0,
        )
        sub_id = sub["id"]

    # -- 1) 提交事件走三阶段 --------------------------------------------------
    payload1 = {"b": 2, "a": {"z": 1, "y": [1, 2, 3]}, "中": "文"}
    row, dup = await payload_service.submit_event(
        pool, store, "orders", "evt-1", payload1
    )
    check("首次提交 duplicate=False", dup is False)
    check("事件记录了内容地址", bool(row["payload_sha256"]))
    sha1 = row["payload_sha256"]
    key1 = object_key(sha1)

    async with pool.acquire() as conn:
        meta = await repo.get_payload_status(conn, sha1)
        n_del = await conn.fetchval(
            "SELECT count(*) FROM deliveries d JOIN events e ON e.id=d.event_id_fk "
            "WHERE e.event_id='evt-1' AND d.subscription_id=$1", sub_id
        )
        obj = await store.get_object(key1)
    check("目录状态 committed", meta["status"] == "committed")
    check("对象已上传且字节为规范化 JSON", json.loads(obj) == payload1)
    check("为订阅创建了 1 条投递", n_del == 1, f"n={n_del}")
    check("对象 key 形态", key1 == f"payloads/{sha1[:2]}/{sha1}")

    # 规范化摘要自检
    expected_sha, expected_body = content_address(payload1)
    check("对象内容即规范化字节", obj == expected_body)
    check("sha 与规范化一致", sha1 == expected_sha)

    # -- 2) 重复提交 + 内容去重 -----------------------------------------------
    row2, dup2 = await payload_service.submit_event(
        pool, store, "orders", "evt-1", payload1
    )
    check("重复提交 duplicate=True", dup2 is True)
    check("重复提交返回同一事件", row2["id"] == row["id"])
    async with pool.acquire() as conn:
        n_del2 = await conn.fetchval(
            "SELECT count(*) FROM deliveries d JOIN events e ON e.id=d.event_id_fk "
            "WHERE e.event_id='evt-1' AND d.subscription_id=$1", sub_id
        )
    check("重复提交不新增投递", n_del2 == 1, f"n={n_del2}")

    # 键顺序不同但语义相同 -> 同一对象（不同 event_id）
    row3, dup3 = await payload_service.submit_event(
        pool, store, "orders", "evt-1b", {"中": "文", "a": {"y": [1, 2, 3], "z": 1}, "b": 2}
    )
    check("语义相同载荷去重到同一 sha", row3["payload_sha256"] == sha1)
    async with pool.acquire() as conn:
        n_obj = await repo.count_committed_payloads(conn)
    check("目录中只有 1 个去重对象", n_obj == 1, f"n={n_obj}")

    # 不同载荷 -> 新对象
    row4, _ = await payload_service.submit_event(
        pool, store, "orders", "evt-2", {"x": 1}
    )
    check("不同载荷得到不同 sha", row4["payload_sha256"] != sha1)

    # -- 3) 双读解析（默认双写 JSONB on）--------------------------------------
    async with pool.acquire() as conn:
        ev = await repo.get_event(conn, row["id"])
    resolved = await payload_service.resolve_event_payload(pool, store, ev)
    check("JSONB 副本双读返回载荷", resolved == payload1)

    # -- 4) 阶段 1/2 崩溃模拟 --------------------------------------------------
    crash_payload = {"crash": "orphan"}
    csha, cbody = content_address(crash_payload)
    ckey = object_key(csha)
    async with pool.acquire() as conn:
        async with payload_service._sha_advisory_lock(conn, csha):
            await repo.begin_event_payload(conn, csha, ckey, len(cbody))
    await store.put_payload_if_absent(ckey, cbody, csha)  # 阶段 2 后“崩溃”
    async with pool.acquire() as conn:
        st = await repo.get_payload_status(conn, csha)
    check("崩溃残留为 uploading", st["status"] == "uploading")
    # 重启后重新提交 -> 幂等接管完成
    row5, dup5 = await payload_service.submit_event(
        pool, store, "orders", "evt-crash", crash_payload
    )
    check("崩溃后重新提交成功", not dup5 and row5["payload_sha256"] == csha)
    async with pool.acquire() as conn:
        st2 = await repo.get_payload_status(conn, csha)
    check("接管后状态 committed", st2["status"] == "committed")

    # 真正的孤儿：uploading 行 + 对象，之后再也没人提交（另一 sha）
    orphan_payload = {"orphan": True}
    osha, obody = content_address(orphan_payload)
    okey = object_key(osha)
    async with pool.acquire() as conn:
        async with payload_service._sha_advisory_lock(conn, osha):
            await repo.begin_event_payload(conn, osha, okey, len(obody))
    await store.put_payload_if_absent(okey, obody, osha)

    # 桶内无目录孤儿对象（阶段 1 之前目录行已不在）
    ghost_payload = {"ghost": 1}
    gsha, gbody = content_address(ghost_payload)
    gkey = object_key(gsha)
    await store.put_payload_if_absent(gkey, gbody, gsha)  # 直接放桶，无目录

    # -- 5) Worker 摘要复核：损坏对象 -> payload_error -------------------------
    tampered = {"tamper": 1}
    tsha, tbody = content_address(tampered)
    tkey = object_key(tsha)
    rowT, _ = await payload_service.submit_event(
        pool, store, "orders", "evt-tamper", tampered
    )
    # 提交完成后篡改对象字节（模拟不可变对象被破坏/替换）
    store._client.put_object(
        Bucket=store.bucket, Key=tkey, Body=b"tampered-bytes-different-length"
    )
    try:
        await payload_service.fetch_and_verify(store, tsha, tkey)
        check("损坏对象摘要复核抛错", False)
    except payload_service.PayloadUnavailable as exc:
        check("损坏对象摘要复核抛 payload_digest_mismatch",
              exc.code == "payload_digest_mismatch")
    # 恢复对象（模拟修复）：put-if-absent 会拒绝覆盖损坏内容，
    # 运维侧用底层客户端按内容地址重写回正确字节后，复核应再次通过。
    store._client.put_object(
        Bucket=store.bucket, Key=tkey, Body=tbody,
        ContentType="application/json",
        Metadata={"sha256": tsha, "kind": "event-payload"},
    )
    recovered = await payload_service.fetch_and_verify(store, tsha, tkey)
    check("对象修复后复核通过", recovered == tampered)

    # -- 6) GC（grace=0）：回收 uploading 残留 + 桶内孤儿，保留被引用对象 ------
    from app.objadmin import _gc

    # osha 仍是 uploading 且无引用 -> abandoned；gkey 是无目录孤儿
    code = await _gc(0, 100, True, close=False)
    check("gc 返回 0", code == 0)
    # 阶段一登记 + 立即阶段二（grace=0）：对象应已删除
    check("abandoned 对象已删除", await _missing(store, okey))
    check("orphan 对象已删除", await _missing(store, gkey))
    check("被引用对象仍存在", not await _missing(store, key1))
    check("tamper 对象仍存在（事件引用）", not await _missing(store, tkey))
    async with pool.acquire() as conn:
        o_meta = await repo.get_payload_status(conn, osha)
    check("abandoned 目录行已删除", o_meta is None)

    # 再跑一次 GC：幂等无副作用
    await _gc(0, 100, True, close=False)
    check("被引用对象在第二次 GC 后仍存在", not await _missing(store, key1))

    # -- 7) GC 不回收“登记后、删除前被并发引用”的对象（锁串行）----------------
    race_payload = {"race": 1}
    rsha, rbody = content_address(race_payload)
    rkey = object_key(rsha)
    await store.put_payload_if_absent(rkey, rbody, rsha)  # 纯孤儿
    # 阶段一登记
    async with pool.acquire() as conn:
        async with payload_service._sha_advisory_lock(conn, rsha):
            async with conn.transaction():
                st = await repo.register_orphan_claim(
                    conn, rsha, rkey, "orphan_object",
                    datetime.now(timezone.utc),
                )
    check("孤儿登记成功", st == "registered")
    # 删除前并发提交引用了它（提交持同锁：先 upsert uploading，再走完成）
    rowR, _ = await payload_service.submit_event(
        pool, store, "orders", "evt-race", race_payload
    )
    check("并发提交复用了曾登记回收的对象", rowR["payload_sha256"] == rsha)
    # GC 阶段二：引用复核必须判定不可删 -> cancelled，对象保留
    await _gc(0, 100, False, close=False)
    check("被并发引用的对象未被删除", not await _missing(store, rkey))
    async with pool.acquire() as conn:
        claim = await conn.fetchrow(
            "SELECT status FROM payload_gc_claims WHERE sha256=$1", rsha
        )
        meta_r = await repo.get_payload_status(conn, rsha)
    check("GC 凭证取消", claim["status"] == "cancelled")
    check("目录状态已推进 committed", meta_r["status"] == "committed")

    # 7b) abandoned 凭证：删除后同 sha 再被提交，凭证复活且不阻止提交 -----
    ab_payload = {"ab": 1}
    asha, abody = content_address(ab_payload)
    akey = object_key(asha)
    async with pool.acquire() as conn:
        async with payload_service._sha_advisory_lock(conn, asha):
            await repo.begin_event_payload(conn, asha, akey, len(abody))
    await store.put_payload_if_absent(akey, abody, asha)
    # 第一轮 GC：登记 + 删除（grace=0）
    await _gc(0, 100, False, close=False)
    check("abandoned 对象已被首轮 GC 删除", await _missing(store, akey))
    # 同 sha 之后被真正提交：阶段 3 头校验发现对象缺失则重传，提交成功
    rowA, dupA = await payload_service.submit_event(
        pool, store, "orders", "evt-ab-late", ab_payload
    )
    check("删除后迟到的同 sha 提交成功", not dupA and rowA["payload_sha256"] == asha)
    check("迟到提交后对象被重传", not await _missing(store, akey))
    async with pool.acquire() as conn:
        meta_a = await repo.get_payload_status(conn, asha)
        claim_a = await conn.fetchrow(
            "SELECT status FROM payload_gc_claims WHERE sha256=$1", asha
        )
    check("迟到提交目录为 committed", meta_a["status"] == "committed")
    check("旧 abandoned 凭证不再是 registered（不会二次误删）",
          claim_a["status"] in {"deleted", "cancelled"})
    # 再跑 GC：已被引用，凭证若被复活也必须再次取消，对象必须保留
    await _gc(0, 100, False, close=False)
    check("再次 GC 后被引用对象保留", not await _missing(store, akey))
    async with pool.acquire() as conn:
        meta_a2 = await repo.get_payload_status(conn, asha)
    check("再次 GC 后目录仍 committed", meta_a2["status"] == "committed")

    # -- 8) 在线迁移旧 JSONB 事件 ----------------------------------------------
    async with pool.acquire() as conn:
        # 造两条旧事件（无 sha；带 JSONB）+ 对应投递
        e_old1 = await conn.fetchval(
            "INSERT INTO events (source, event_id, payload, payload_sha256) "
            "VALUES ('orders','evt-old1',$1::jsonb,NULL) RETURNING id",
            {"old": 1},
        )
        e_old2 = await conn.fetchval(
            "INSERT INTO events (source, event_id, payload, payload_sha256) "
            "VALUES ('orders','evt-old2',$1::jsonb,NULL) RETURNING id",
            {"old": 2},
        )
        ver = await conn.fetchval(
            "SELECT id FROM subscription_versions WHERE subscription_id=$1 "
            "ORDER BY revision DESC LIMIT 1", sub_id
        )
        for eid in (e_old1, e_old2):
            await conn.execute(
                "INSERT INTO deliveries (event_id_fk, subscription_id, "
                "config_version_id, chain_id, chain_seq, status) "
                "VALUES ($1,$2,$3,nextval('delivery_chain_seq'),1,'pending')",
                eid, sub_id, ver,
            )
    # 迁移中断模拟：batch_size=1
    from app.objadmin import _migrate, _drop_jsonb, _dual_write

    rc = await _migrate(1, close=False)
    check("migrate 第一批 rc=0", rc == 0)  # 循环会跑完两批
    async with pool.acquire() as conn:
        remaining = await repo.count_legacy_payload_events(conn)
    check("迁移后无旧 JSONB-only 事件", remaining == 0, f"remaining={remaining}")
    # 迁移幂等：再跑一次
    await _migrate(1, close=False)
    async with pool.acquire() as conn:
        n_run = await conn.fetchval("SELECT count(*) FROM payload_migrations WHERE status='completed'")
    check("迁移运行记录完成", n_run >= 1)

    # 旧事件双读：现在 payload 列还在（双写 on）-> 优先 JSONB；切到对象也可
    async with pool.acquire() as conn:
        ev_old = await repo.get_event(conn, e_old1)
    p_old = await payload_service.resolve_event_payload(pool, store, ev_old)
    check("迁移后旧事件双读正常", p_old == {"old": 1})

    # 关双写 + drop JSONB
    await _dual_write(False, close=False)
    await _drop_jsonb(1, close=False)
    async with pool.acquire() as conn:
        dual = await repo.count_dual_copy_events(conn)
        ev_old2 = await repo.get_event(conn, e_old2)
    check("JSONB 副本已全部释放", dual == 0, f"dual={dual}")
    p_old2 = await payload_service.resolve_event_payload(pool, store, ev_old2)
    check("纯对象路径读取 + 摘要校验", p_old2 == {"old": 2})

    # 关闭双写后新事件不再写 JSONB
    rowN, _ = await payload_service.submit_event(
        pool, store, "orders", "evt-new-nodual", {"k": "v"}
    )
    check("双写关闭后事件无 JSONB 副本", rowN["payload"] is None)

    # -- 9) status 端点所需聚合不报错 ------------------------------------------
    async with pool.acquire() as conn:
        claims = await repo.count_gc_claims(conn)
    check("GC 凭证聚合", isinstance(claims, dict) and claims.get("deleted", 0) >= 2,
          str(claims))

    await dbmod.close_pool()
    print(f"\n通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("失败:", *FAILED, sep="\n - ")
        sys.exit(1)


async def _missing(store, key):
    from app.object_store import ObjectNotFound

    try:
        await store.get_object(key)
        return False
    except ObjectNotFound:
        return True


if __name__ == "__main__":
    asyncio.run(main())
