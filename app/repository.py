"""领域数据访问：事件、订阅、订阅配置版本、投递、投递尝试。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg

from app import envelope
from app.config import settings
from app.keyring import Keyring


class ReplayError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ConfigConflictError(Exception):
    """发布新版本时 expected_revision 与当前版本不一致（CAS 失败）。"""

    def __init__(self, current_revision: int):
        super().__init__(
            f"配置版本已变更：expected_revision 已过期，当前版本为 {current_revision}"
        )
        self.code = "revision_conflict"
        self.current_revision = current_revision


# -- 行 -> dict 映射 -----------------------------------------------------------

DELIVERY_COLUMNS = """
    d.id, d.event_id_fk, d.subscription_id, d.config_version_id,
    d.chain_id, d.chain_seq, d.status, d.attempts_made, d.not_before,
    d.leased_at, d.lease_expires_at, d.leased_by,
    d.created_at, d.updated_at
"""

# 版本查询返回的非敏感字段（绝不包含 secret 明文，也不包含密文/包裹的 DEK）
VERSION_COLUMNS = """
    v.id AS version_id, v.subscription_id, v.revision, v.target_url,
    v.max_attempts, v.backoff_base_seconds, v.backoff_cap_seconds,
    v.created_at, v.superseded_at, v.secret_key_id
"""


def delivery_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    data = dict(row)
    # JOIN 出来的展示字段（可能不存在）
    return data


# -- 订阅 ----------------------------------------------------------------------

async def _encrypt_version_secret(
    conn: asyncpg.Connection,
    keyring: Keyring,
    subscription_id: int,
    version_id: int,
    secret: str,
) -> None:
    """为刚插入的配置版本生成随机 DEK 并信封加密其 HMAC 密钥。

    AAD 绑定 (subscription_id, version_id)；只写密文/包裹的 DEK/key_id，
    secret 明文列保持空串，明文不落盘。与插入版本行处于同一事务。
    """
    ciphertext, wrapped_dek, key_id = envelope.encrypt_new_secret(
        keyring, subscription_id, version_id, secret
    )
    await conn.execute(
        """
        UPDATE subscription_versions
        SET secret_ciphertext = $2,
            secret_dek_wrapped = $3,
            secret_key_id = $4
        WHERE id = $1
        """,
        version_id,
        ciphertext,
        wrapped_dek,
        key_id,
    )


async def create_subscription(
    conn: asyncpg.Connection,
    source: str,
    target_url: str,
    secret: str,
    *,
    keyring: Keyring,
    max_attempts: int,
    backoff_base_seconds: float,
    backoff_cap_seconds: float,
) -> asyncpg.Record:
    """新建订阅并原子写入不可变的初始配置版本 revision=1（密钥信封加密）。

    (source, target_url) 已存在时仅重新激活（配置不变，沿用其当前版本）。
    返回订阅行（含 current_revision）。
    """
    async with conn.transaction():
        sub = await conn.fetchrow(
            """
            INSERT INTO subscriptions (source, target_url, secret, current_revision)
            VALUES ($1, $2, '', 1)
            ON CONFLICT (source, target_url) DO UPDATE
                SET active = TRUE
            RETURNING id, source, target_url, active, created_at, current_revision,
                      (xmax = 0) AS inserted
            """,
            source,
            target_url,
        )
        # 仅对真正新建的订阅追加 revision=1；已存在的订阅其版本历史保持不变。
        if sub["inserted"]:
            version_id = await conn.fetchval(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret, max_attempts,
                     backoff_base_seconds, backoff_cap_seconds)
                VALUES ($1, 1, $2, '', $3, $4, $5)
                RETURNING id
                """,
                sub["id"],
                target_url,
                max_attempts,
                backoff_base_seconds,
                backoff_cap_seconds,
            )
            await _encrypt_version_secret(
                conn, keyring, sub["id"], version_id, secret
            )
        return sub


async def get_subscription_by_id(
    conn: asyncpg.Connection, subscription_id: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT id, source, target_url, active, current_revision, created_at
        FROM subscriptions WHERE id = $1
        """,
        subscription_id,
    )


async def find_subscription(
    conn: asyncpg.Connection, source: str, target_url: str
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT id, source, target_url, active, current_revision, created_at
        FROM subscriptions WHERE source = $1 AND target_url = $2
        """,
        source,
        target_url,
    )


async def list_subscriptions(
    conn: asyncpg.Connection, source: str | None
) -> list[asyncpg.Record]:
    if source is not None:
        rows = await conn.fetch(
            """
            SELECT id, source, target_url, active, current_revision, created_at
            FROM subscriptions WHERE source = $1 ORDER BY id
            """,
            source,
        )
    else:
        rows = await conn.fetch(
            """
            SELECT id, source, target_url, active, current_revision, created_at
            FROM subscriptions ORDER BY id
            """
        )
    return list(rows)


# -- 订阅配置版本 / CAS 发布 ----------------------------------------------------

async def publish_version(
    conn: asyncpg.Connection,
    *,
    keyring: Keyring,
    subscription_id: int,
    target_url: str,
    secret: str,
    max_attempts: int,
    backoff_base_seconds: float,
    backoff_cap_seconds: float,
    expected_revision: int,
) -> tuple[asyncpg.Record, int]:
    """以 CAS 方式发布新的不可变配置版本，并原子确定切换边界。

    - 必须携带 expected_revision；与 subscriptions.current_revision 不一致则抛
      ConfigConflictError（并发发布只有一个能成功）。
    - 同一事务内：关闭旧版本边界（superseded_at=now）、追加新版本（密钥信封
      加密，AAD 绑定新 version_id）、推进 current_revision。事件提交事务会先锁
      订阅行，因此与发布竞争的事件要么在边界前（钉旧版本）、要么在边界后
      （用新版本），不存在跨界。
    - 不修改任何旧版本行；已存在的投递永远引用各自创建时的版本。

    返回 (新版本行, 新 revision)。
    """
    async with conn.transaction():
        # 行锁串行化同一订阅上的所有发布与事件提交，保证唯一切换边界。
        sub = await conn.fetchrow(
            """
            SELECT id, current_revision
            FROM subscriptions
            WHERE id = $1
            FOR UPDATE
            """,
            subscription_id,
        )
        if sub is None:
            raise LookupError("subscription not found")
        if sub["current_revision"] != expected_revision:
            raise ConfigConflictError(sub["current_revision"])

        new_revision = expected_revision + 1
        await conn.execute(
            """
            UPDATE subscription_versions
            SET superseded_at = now()
            WHERE subscription_id = $1
              AND revision = $2
              AND superseded_at IS NULL
            """,
            subscription_id,
            expected_revision,
        )
        version_id = await conn.fetchval(
            """
            INSERT INTO subscription_versions
                (subscription_id, revision, target_url, secret, max_attempts,
                 backoff_base_seconds, backoff_cap_seconds)
            VALUES ($1, $2, $3, '', $4, $5, $6)
            RETURNING id
            """,
            subscription_id,
            new_revision,
            target_url,
            max_attempts,
            backoff_base_seconds,
            backoff_cap_seconds,
        )
        await _encrypt_version_secret(
            conn, keyring, subscription_id, version_id, secret
        )
        version = await conn.fetchrow(
            f"""
            SELECT {VERSION_COLUMNS}
            FROM subscription_versions v
            WHERE v.id = $1
            """,
            version_id,
        )
        # 冗余的 subscriptions.target_url 仅为兼容旧列随当前版本同步；
        # secret 冗余列不再保存明文（统一置空，权威密钥在版本表的密文列中）。
        await conn.execute(
            """
            UPDATE subscriptions
            SET current_revision = $2, target_url = $3, secret = ''
            WHERE id = $1
            """,
            subscription_id,
            new_revision,
            target_url,
        )
        return version, new_revision


async def list_versions(
    conn: asyncpg.Connection, subscription_id: int
) -> list[asyncpg.Record]:
    """列出某订阅全部配置版本（按 revision 升序）；不返回 secret。"""
    rows = await conn.fetch(
        f"""
        SELECT {VERSION_COLUMNS},
               (v.revision = s.current_revision) AS is_current
        FROM subscription_versions v
        JOIN subscriptions s ON s.id = v.subscription_id
        WHERE v.subscription_id = $1
        ORDER BY v.revision
        """,
        subscription_id,
    )
    return list(rows)


async def get_current_version(
    conn: asyncpg.Connection, subscription_id: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        f"""
        SELECT {VERSION_COLUMNS}, TRUE AS is_current
        FROM subscription_versions v
        JOIN subscriptions s ON s.id = v.subscription_id
        WHERE v.subscription_id = $1 AND v.revision = s.current_revision
        """,
        subscription_id,
    )


# -- 事件与投递创建 -------------------------------------------------------------
#
# 载荷内容寻址 + 持久化提交状态机（对象存储与数据库的两阶段协调）：
#
#   阶段 1（begin）：事务内 upsert event_payloads(status='uploading') 并提交。
#       行先于对象存在，是“即将上传对象 sha=X”的持久化意图；崩溃后该行可被
#       下一次同摘要提交幂等接管，或在宽限期后被 GC 回收。
#   阶段 2（对象上传，无数据库事务）：按内容地址幂等上传不可变对象，
#       已存在即复用（相同 sha 字节必然相同）。
#   阶段 3（commit）：事务内把状态推进为 committed，同一事务插入事件与投递。
#       事件外键只接受 committed 对象，因此不存在悬空引用；重复提交时
#       事件唯一冲突 -> 不插入任何投递（幂等）。
#
# 不变量：对象可能暂时多于目录（孤儿对象，GC 负责），但目录中 committed 的
# 对象在被事件引用期间必然存在；任何时刻对外可见的事件都指向完整对象。


async def begin_event_payload(
    conn: asyncpg.Connection, sha: str, object_key: str, size_bytes: int
) -> None:
    """阶段 1：登记（或接管）上传意图并提交。

    已存在 committed 行：对象此前已上传，幂等返回（上传仍会做 head 复核）。
    已存在 uploading 行：崩溃残留或并发提交，幂等接管（不改时间戳，避免
    不断刷新 updated_at 导致 GC 宽限期永远无法到达）。
    """
    async with conn.transaction():
        await conn.execute(
            """
            INSERT INTO event_payloads (sha256, object_key, size_bytes, status)
            VALUES ($1, $2, $3, 'uploading')
            ON CONFLICT (sha256) DO NOTHING
            """,
            sha,
            object_key,
            size_bytes,
        )


async def commit_event(
    conn: asyncpg.Connection,
    *,
    source: str,
    event_id: str,
    payload: dict[str, Any] | None,
    sha: str,
    dual_write_jsonb: bool,
) -> tuple[asyncpg.Record, bool]:
    """阶段 3：提交对象状态机并原子写入事件与投递（单事务）。

    - event_payloads 行进 committed（幂等；必须存在阶段 1 的 uploading 行）；
    - 插入事件（(source, event_id) 冲突即重复提交：不新增任何投递）；
    - 迁移/双写开关开启时同时写 payload JSONB，供旧版本进程双读；
    - 为该 source 的所有活跃订阅创建投递，固化当前配置版本。

    与发布新版本的边界：先对该 source 的活跃订阅行加 FOR UPDATE 行锁，
    与 publish_version 互斥；每条新投递必然落在切换边界的确定一侧。
    返回 (event 行, 是否重复提交)。
    """
    async with conn.transaction():
        # 状态机推进：对象已上传完毕，目录行才允许 committed。
        # updated_at 只在 uploading -> committed 时推进。
        await conn.execute(
            """
            UPDATE event_payloads
            SET status = 'committed',
                committed_at = COALESCE(committed_at, now()),
                updated_at = now()
            WHERE sha256 = $1
            """,
            sha,
        )
        event_row = await conn.fetchrow(
            """
            INSERT INTO events (source, event_id, payload, payload_sha256)
            VALUES ($1, $2, $3::jsonb, $4)
            ON CONFLICT (source, event_id) DO NOTHING
            RETURNING id, source, event_id, payload, payload_sha256, created_at
            """,
            source,
            event_id,
            payload if dual_write_jsonb else None,
            sha,
        )
        duplicate = event_row is None
        if duplicate:
            event_row = await conn.fetchrow(
                """
                SELECT id, source, event_id, payload, payload_sha256, created_at
                FROM events WHERE source = $1 AND event_id = $2
                """,
                source,
                event_id,
            )
            return event_row, True

        # 锁住该 source 的活跃订阅：与版本发布串行，读 current_revision 时无竞态。
        await conn.execute(
            """
            SELECT id FROM subscriptions
            WHERE source = $1 AND active = TRUE
            ORDER BY id
            FOR UPDATE
            """,
            source,
        )
        await conn.execute(
            """
            INSERT INTO deliveries
                (event_id_fk, subscription_id, config_version_id,
                 chain_id, chain_seq, status)
            SELECT e.id, s.id, v.id, nextval('delivery_chain_seq'), 1, 'pending'
            FROM events e
            JOIN subscriptions s ON s.source = $2 AND s.active = TRUE
            JOIN subscription_versions v
                 ON v.subscription_id = s.id AND v.revision = s.current_revision
            WHERE e.id = $1
            """,
            event_row["id"],
            source,
        )
        return event_row, False


async def get_meta_flag(conn: asyncpg.Connection, key: str, default: bool) -> bool:
    """读取 app_meta 中的布尔开关（不存在返回 default）。

    存储格式为 JSON 对象 {"enabled": true/false}（不能存 JSON 标量字符串
    "false"——Python 中非空字符串会被当成真）。
    """
    value = await conn.fetchval("SELECT value FROM app_meta WHERE key = $1", key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return bool(value.get("enabled"))
    return default


async def set_meta_flag(conn: asyncpg.Connection, key: str, value: bool) -> None:
    await conn.execute(
        """
        INSERT INTO app_meta (key, value, updated_at)
        VALUES ($1, $2::jsonb, now())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """,
        key,
        {"enabled": value},
    )


async def get_event(
    conn: asyncpg.Connection, event_pk: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT id, source, event_id, payload, payload_sha256, created_at
        FROM events WHERE id = $1
        """,
        event_pk,
    )


# -- Worker：认领队首任务 --------------------------------------------------------

# 严格顺序的关键：
# 1) 先在事务中锁定该订阅“可投递且 seq 最小”的那一条（FOR UPDATE SKIP LOCKED）；
# 2) 检查它前面是否还有未终结的投递，有则跳过（保证前一事件成功或进死信后才动）；
# 3) 用 lease_token 栅栏把它置为 in_flight，旧租约必须已过期才可接管。
# 认领/重试/接管一律不改变 config_version_id：投递钉死在创建时的版本上。
async def claim_delivery(
    conn: asyncpg.Connection, worker_id: str
) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    lease_seconds = settings.lease_seconds
    lease_expires = now + timedelta(seconds=lease_seconds)
    lease_token = f"{worker_id}:{now.timestamp()}"

    async with conn.transaction():
        # 候选：每个订阅 seq 最小的可处理投递（pending 到点 或 租约过期的 in_flight）。
        # NOT EXISTS 保证严格顺序：前面还有未终结投递时不允许发送后续事件。
        candidate = await conn.fetchrow(
            """
            SELECT d.id, d.event_id_fk, d.subscription_id, d.status,
                   d.attempts_made, d.leased_by
            FROM deliveries d
            WHERE (
                    (d.status = 'pending' AND d.not_before <= $1)
                 OR (d.status = 'in_flight' AND d.lease_expires_at < $1)
                )
              AND NOT EXISTS (
                    SELECT 1
                    FROM subscriptions s
                    WHERE s.id = d.subscription_id AND s.active = FALSE
              )
              AND NOT EXISTS (
                    SELECT 1
                    FROM deliveries earlier
                    WHERE earlier.subscription_id = d.subscription_id
                      AND earlier.seq < d.seq
                      AND earlier.status IN ('pending', 'in_flight')
              )
            ORDER BY d.seq
            LIMIT 1
            FOR UPDATE OF d SKIP LOCKED
            """,
            now,
        )
        if candidate is None:
            return None

        updated = await conn.fetchrow(
            """
            UPDATE deliveries
            SET status = 'in_flight',
                leased_at = $2,
                lease_expires_at = $3,
                leased_by = $4,
                updated_at = $2
            WHERE id = $1
            RETURNING id, event_id_fk, subscription_id, config_version_id,
                      chain_id, chain_seq, attempts_made, status, not_before
            """,
            candidate["id"],
            now,
            lease_expires,
            lease_token,
        )
        if updated is None:
            return None

        return {
            "delivery": updated,
            "lease_token": lease_token,
            "leased_at": now,
            "lease_expires_at": lease_expires,
        }


async def load_delivery_context(
    conn: asyncpg.Connection, delivery_id: int
) -> asyncpg.Record | None:
    """加载投递上下文；target_url/密钥材料/重试参数全部取自投递钉住的版本。

    因而切换边界前创建的投递及其后续重试、接管，永远使用旧版本的 URL 与密钥。
    密钥的密文/包裹 DEK 在此一并取出，由 Worker 在签名前才解密（见
    app/envelope.py）；旧格式（迁移未完成）则回退读取 secret 明文列。

    事件载荷只返回内容地址（sha + object_key）与迁移期双读兜底的 JSONB：
    Worker 从对象存储取字节并复核 SHA-256 后才签名投递（见 app/worker.py）。
    """
    return await conn.fetchrow(
        """
        SELECT d.id AS delivery_id,
               d.attempts_made,
               e.id AS event_pk,
               e.source,
               e.event_id,
               e.payload AS legacy_payload,
               e.payload_sha256,
               p.object_key,
               p.status AS payload_status,
               s.id AS subscription_pk,
               v.id AS config_version_pk,
               v.revision AS config_revision,
               v.target_url,
               v.secret,
               v.secret_ciphertext,
               v.secret_dek_wrapped,
               v.secret_key_id,
               v.max_attempts,
               v.backoff_base_seconds,
               v.backoff_cap_seconds
        FROM deliveries d
        JOIN events e ON e.id = d.event_id_fk
        LEFT JOIN event_payloads p ON p.sha256 = e.payload_sha256
        JOIN subscriptions s ON s.id = d.subscription_id
        JOIN subscription_versions v ON v.id = d.config_version_id
        WHERE d.id = $1
        """,
        delivery_id,
    )


# -- Worker：记录尝试并结算 ------------------------------------------------------

async def record_attempt(
    conn: asyncpg.Connection,
    *,
    delivery_id: int,
    lease_token: str,
    worker_id: str,
    outcome: str,
    http_status: int | None,
    response_excerpt: str | None,
    error_message: str | None,
    leased_at: datetime,
    lease_expires_at: datetime,
) -> int | None:
    """在租约持有方身份校验通过后追加一条尝试记录并 attempts_made+1。

    返回新的 attempt_number；若租约已被接管则返回 None（本次结果作废）。
    """
    async with conn.transaction():
        locked = await conn.fetchrow(
            """
            SELECT leased_by FROM deliveries
            WHERE id = $1 FOR UPDATE
            """,
            delivery_id,
        )
        if locked is None or locked["leased_by"] != lease_token:
            return None

        attempt_number = await conn.fetchval(
            """
            INSERT INTO delivery_attempts
                (delivery_id, attempt_number, worker_id, outcome, http_status,
                 response_excerpt, error_message, leased_at, lease_expires_at,
                 finished_at)
            SELECT $1, COALESCE(MAX(attempt_number), 0) + 1, $2, $3, $4, $5, $6,
                   $7, $8, now()
            FROM delivery_attempts
            WHERE delivery_id = $1
            RETURNING attempt_number
            """,
            delivery_id,
            worker_id,
            outcome,
            http_status,
            response_excerpt,
            error_message,
            leased_at,
            lease_expires_at,
        )
        await conn.execute(
            "UPDATE deliveries SET attempts_made = attempts_made + 1, updated_at = now() WHERE id = $1",
            delivery_id,
        )
        return attempt_number


async def settle_delivery(
    conn: asyncpg.Connection,
    *,
    delivery_id: int,
    lease_token: str,
    succeeded: bool,
    not_before: datetime | None,
    max_attempts: int,
) -> str | None:
    """根据本次尝试结果结算。

    成功 -> succeeded；失败且已达该投递所钉版本的 max_attempts -> dead_lettered；
    否则回到 pending 并设置指数退避时间。返回结算后的状态；租约失效返回 None。
    """
    async with conn.transaction():
        locked = await conn.fetchrow(
            """
            SELECT attempts_made, leased_by FROM deliveries
            WHERE id = $1 FOR UPDATE
            """,
            delivery_id,
        )
        if locked is None or locked["leased_by"] != lease_token:
            return None

        if succeeded:
            status = "succeeded"
        elif locked["attempts_made"] >= max_attempts:
            status = "dead_lettered"
        else:
            status = "pending"

        await conn.execute(
            """
            UPDATE deliveries
            SET status = $2,
                not_before = COALESCE($3, now()),
                leased_at = NULL,
                lease_expires_at = NULL,
                leased_by = NULL,
                updated_at = now()
            WHERE id = $1
            """,
            delivery_id,
            status,
            not_before,
        )
        return status


# -- 查询：历史 / 死信 -----------------------------------------------------------

_DELIVERY_SELECT = f"""
    SELECT {DELIVERY_COLUMNS},
           e.source AS event_source,
           e.event_id AS source_event_id,
           v.target_url AS target_url,
           v.revision AS config_revision,
           v.id AS config_version_pk,
           v.created_at AS config_effective_at
    FROM deliveries d
    JOIN events e ON e.id = d.event_id_fk
    JOIN subscriptions s ON s.id = d.subscription_id
    JOIN subscription_versions v ON v.id = d.config_version_id
"""


async def list_deliveries(
    conn: asyncpg.Connection,
    *,
    status: str | None = None,
    subscription_id: int | None = None,
    config_revision: int | None = None,
    source: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        _DELIVERY_SELECT
        + """
        WHERE ($1::text IS NULL OR d.status = $1)
          AND ($2::bigint IS NULL OR d.subscription_id = $2)
          AND ($3::text IS NULL OR e.source = $3)
          AND ($4::int IS NULL OR v.revision = $4)
        ORDER BY d.id DESC
        LIMIT $5 OFFSET $6
        """,
        status,
        subscription_id,
        source,
        config_revision,
        limit,
        offset,
    )
    return list(rows)


async def get_delivery(
    conn: asyncpg.Connection, delivery_id: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        _DELIVERY_SELECT + " WHERE d.id = $1",
        delivery_id,
    )


async def list_attempts(
    conn: asyncpg.Connection, delivery_id: int
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id, attempt_number, worker_id, started_at, finished_at, outcome,
               http_status, response_excerpt, error_message,
               leased_at, lease_expires_at
        FROM delivery_attempts
        WHERE delivery_id = $1
        ORDER BY attempt_number
        """,
        delivery_id,
    )
    return list(rows)


async def list_deliveries_for_event(
    conn: asyncpg.Connection, event_pk: int
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        _DELIVERY_SELECT + " WHERE d.event_id_fk = $1 ORDER BY d.id",
        event_pk,
    )
    return list(rows)


# -- 死信重放 --------------------------------------------------------------------

async def replay_dead_letter(
    conn: asyncpg.Connection, delivery_id: int, *, use_current_version: bool = False
) -> tuple[asyncpg.Record, int]:
    """为死信投递新建一条投递链记录（同 chain_id，chain_seq+1），保留旧记录。

    配置版本固化在新投递上：
    - 默认沿用原投递钉住的版本（死信重放不改变 URL/密钥/重试参数）；
    - use_current_version=True 时显式选用订阅当前版本。

    原投递为非死信状态时抛 ReplayError(not_dead_lettered)；链上已有活动投递时
    抛 ReplayError(chain_busy)。返回新投递行（含 config_revision）。
    """
    async with conn.transaction():
        original = await conn.fetchrow(
            """
            SELECT d.id, d.event_id_fk, d.subscription_id, d.chain_id, d.chain_seq,
                   d.status, d.config_version_id
            FROM deliveries d
            WHERE d.id = $1
            FOR UPDATE
            """,
            delivery_id,
        )
        if original is None:
            raise LookupError("delivery not found")
        if original["status"] != "dead_lettered":
            raise ReplayError("not_dead_lettered", "只有死信状态的投递可以重放")

        busy = await conn.fetchval(
            """
            SELECT 1 FROM deliveries
            WHERE subscription_id = $1
              AND chain_id = $2
              AND status IN ('pending', 'in_flight')
            LIMIT 1
            """,
            original["subscription_id"],
            original["chain_id"],
        )
        if busy is not None:
            raise ReplayError("chain_busy", "该重放链上已有待投递/投递中的任务")

        if use_current_version:
            # 锁订阅行，与发布竞争时明确取已提交的当前版本。
            current = await conn.fetchrow(
                """
                SELECT v.id AS config_version_id, v.revision AS config_revision
                FROM subscriptions s
                JOIN subscription_versions v
                     ON v.subscription_id = s.id AND v.revision = s.current_revision
                WHERE s.id = $1
                FOR UPDATE OF s
                """,
                original["subscription_id"],
            )
            if current is None:  # 理论上不可能：订阅与版本必然存在
                raise ReplayError("no_current_version", "订阅当前配置版本不存在")
            config_version_id = current["config_version_id"]
            config_revision = current["config_revision"]
        else:
            pinned = await conn.fetchrow(
                """
                SELECT v.id AS config_version_id, v.revision AS config_revision
                FROM subscription_versions v
                WHERE v.id = $1
                """,
                original["config_version_id"],
            )
            config_version_id = pinned["config_version_id"]
            config_revision = pinned["config_revision"]

        # chain_seq 取链上已有最大值 + 1（多次重放时原记录 chain_seq 恒为 1，
        # 不能用 original.chain_seq + 1，否则第二次重放会撞唯一约束）。
        next_seq = await conn.fetchval(
            """
            SELECT COALESCE(MAX(chain_seq), 0) + 1
            FROM deliveries
            WHERE subscription_id = $1 AND chain_id = $2
            """,
            original["subscription_id"],
            original["chain_id"],
        )
        new_row = await conn.fetchrow(
            """
            INSERT INTO deliveries
                (event_id_fk, subscription_id, config_version_id,
                 chain_id, chain_seq, status)
            VALUES ($1, $2, $3, $4, $5, 'pending')
            RETURNING id, event_id_fk, subscription_id, config_version_id,
                      chain_id, chain_seq, status, attempts_made, not_before,
                      leased_at, lease_expires_at, leased_by, created_at, updated_at
            """,
            original["event_id_fk"],
            original["subscription_id"],
            config_version_id,
            original["chain_id"],
            next_seq,
        )
        # 附上 revision 供 API 响应使用
        return new_row, config_revision


# -- 密钥迁移与主密钥轮换（keyadmin） ---------------------------------------------
#
# 两类批处理都按“取一批（FOR UPDATE SKIP LOCKED）→ 处理 → 提交”循环，
# 因此天然幂等、可断点续跑（已处理的行不再满足筛选条件），且多个进程可并发
# 执行互不重复；与在线投递 Worker 并发安全（行级锁，投递读取不受阻塞）。

async def fetch_plaintext_versions_batch(
    conn: asyncpg.Connection, limit: int
) -> list[asyncpg.Record]:
    """取一批仍是明文的配置版本（调用方须在事务内，配合行锁处理）。"""
    rows = await conn.fetch(
        """
        SELECT id, subscription_id, secret
        FROM subscription_versions
        WHERE secret_ciphertext IS NULL
        ORDER BY id
        LIMIT $1
        FOR UPDATE SKIP LOCKED
        """,
        limit,
    )
    return list(rows)


async def mark_version_encrypted(
    conn: asyncpg.Connection,
    version_id: int,
    ciphertext: bytes,
    wrapped_dek: bytes,
    key_id: str,
) -> None:
    """把某版本写为信封格式并清空明文列（同事务保证不丢明文备份）。"""
    await conn.execute(
        """
        UPDATE subscription_versions
        SET secret_ciphertext = $2,
            secret_dek_wrapped = $3,
            secret_key_id = $4,
            secret = ''
        WHERE id = $1
        """,
        version_id,
        ciphertext,
        wrapped_dek,
        key_id,
    )


async def clear_subscription_secret_cache(conn: asyncpg.Connection) -> int:
    """清空 subscriptions.secret 冗余列中的遗留明文，返回清理行数。

    该列仅作兼容冗余，权威配置在版本表；投递链路从不读取它。
    """
    result = await conn.execute(
        "UPDATE subscriptions SET secret = '' WHERE secret <> ''"
    )
    return int(result.split()[-1])


async def fetch_rewrap_batch(
    conn: asyncpg.Connection,
    target_key_id: str,
    limit: int,
    from_key_id: str | None = None,
) -> list[asyncpg.Record]:
    """取一批尚未用目标主密钥包裹的信封版本（调用方须在事务内）。

    from_key_id 指定时只取该来源 key_id 的行。
    """
    rows = await conn.fetch(
        """
        SELECT id, secret_key_id, secret_dek_wrapped
        FROM subscription_versions
        WHERE secret_ciphertext IS NOT NULL
          AND secret_key_id IS DISTINCT FROM $1
          AND ($3::text IS NULL OR secret_key_id = $3)
        ORDER BY id
        LIMIT $2
        FOR UPDATE SKIP LOCKED
        """,
        target_key_id,
        limit,
        from_key_id,
    )
    return list(rows)


async def apply_rewrap(
    conn: asyncpg.Connection, version_id: int, wrapped_dek: bytes, key_id: str
) -> None:
    """更新某版本的 DEK 包裹与 key_id（只重包裹，不动密钥密文本身）。"""
    await conn.execute(
        """
        UPDATE subscription_versions
        SET secret_dek_wrapped = $2,
            secret_key_id = $3
        WHERE id = $1
        """,
        version_id,
        wrapped_dek,
        key_id,
    )


async def start_or_adopt_rotation(
    conn: asyncpg.Connection, new_key_id: str, old_key_id: str
) -> asyncpg.Record:
    """开始或接管一次轮换运行。

    存在同目标的 running（进行中/崩溃残留）或 failed（失败待恢复）记录时
    接管并置回 running，从已持久化的进度断点续跑；否则新建运行。

    返回 (运行记录, 是否为接管)。
    """
    for _attempt in range(2):
        async with conn.transaction():
            existing = await conn.fetchrow(
                """
                SELECT id, old_key_id, new_key_id, status, processed_count,
                       last_version_id, last_error, started_at, updated_at,
                       finished_at
                FROM key_rotations
                WHERE status IN ('running', 'failed') AND new_key_id = $1
                ORDER BY id
                LIMIT 1
                FOR UPDATE
                """,
                new_key_id,
            )
            if existing is not None:
                await conn.execute(
                    """
                    UPDATE key_rotations
                    SET status = 'running', last_error = NULL,
                        old_key_id = $2, updated_at = now(), finished_at = NULL
                    WHERE id = $1
                    """,
                    existing["id"],
                    old_key_id or existing["old_key_id"],
                )
                return existing, True
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO key_rotations (old_key_id, new_key_id, status)
                    VALUES ($2, $1, 'running')
                    RETURNING id, old_key_id, new_key_id, status, processed_count,
                              last_version_id, last_error, started_at, updated_at,
                              finished_at
                    """,
                    new_key_id,
                    old_key_id,
                )
                return row, False
            except asyncpg.UniqueViolationError:
                # 并发创建：另一进程已插入 running 记录；重试即走接管分支。
                continue
    raise RuntimeError("无法创建或接管轮换运行（并发冲突）")


async def update_rotation_progress(
    conn: asyncpg.Connection, rotation_id: int, processed: int, last_version_id: int
) -> None:
    """累加轮换进度（与当批重包裹在同一事务提交，崩溃后进度不超前于数据）。"""
    await conn.execute(
        """
        UPDATE key_rotations
        SET processed_count = processed_count + $2,
            last_version_id = GREATEST(last_version_id, $3),
            updated_at = now()
        WHERE id = $1
        """,
        rotation_id,
        processed,
        last_version_id,
    )


async def finish_rotation(
    conn: asyncpg.Connection, rotation_id: int, status: str, error: str | None = None
) -> None:
    await conn.execute(
        """
        UPDATE key_rotations
        SET status = $2, last_error = $3, updated_at = now(), finished_at = now()
        WHERE id = $1
        """,
        rotation_id,
        status,
        error,
    )


async def list_rotations(
    conn: asyncpg.Connection, limit: int = 10
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id, old_key_id, new_key_id, status, processed_count,
               last_version_id, last_error, started_at, updated_at, finished_at
        FROM key_rotations
        ORDER BY id DESC
        LIMIT $1
        """,
        limit,
    )
    return list(rows)


async def count_versions_by_key_id(conn: asyncpg.Connection) -> list[asyncpg.Record]:
    """按包裹 key_id 统计信封版本数（明文版本不在其中）。"""
    rows = await conn.fetch(
        """
        SELECT secret_key_id AS key_id, COUNT(*) AS n
        FROM subscription_versions
        WHERE secret_ciphertext IS NOT NULL
        GROUP BY secret_key_id
        ORDER BY secret_key_id
        """
    )
    return list(rows)


async def count_plaintext_versions(conn: asyncpg.Connection) -> int:
    return await conn.fetchval(
        "SELECT COUNT(*) FROM subscription_versions WHERE secret_ciphertext IS NULL"
    )


async def count_references_to_key(conn: asyncpg.Connection, key_id: str) -> int:
    """仍引用指定 key_id 的配置版本数（移除旧密钥前的安全检查）。"""
    return await conn.fetchval(
        """
        SELECT COUNT(*) FROM subscription_versions
        WHERE secret_ciphertext IS NOT NULL AND secret_key_id = $1
        """,
        key_id,
    )


# -- 事件载荷：状态机 / 迁移 / 垃圾回收 ------------------------------------------
#
# 垃圾回收的两类目标，均带“引用复核 + 宽限期 + 两阶段”：
# - abandoned_upload：event_payloads 中宽限期后仍为 uploading 且已无事件引用
#   （提交进程崩溃残留）的目录行，连同其（可能存在的）对象一起回收；
# - orphan_object：S3 桶中存在、但数据库目录完全没有的对象（阶段 1 后、
#   阶段 3 前进程被杀；或对象被带外写入）。
#
# 与并发提交/重放的互斥靠两点保证：
# 1) 所有回收决策都在事务内对该 sha 的“资源集合”做行锁/咨询锁串行化——
#    提交协议阶段 1 的 upsert 与 GC 的“无目录行”分支抢同一把按 sha 派生的
#    事务级咨询锁，谁先拿到锁谁先做存在性复核，因此不会出现“GC 刚删完、
#    提交已引用”的窗口；
# 2) 物理删除 S3 对象在宽限期后的第二阶段执行，删除前再次复核目录中无
#    committed 引用、无删除期间新生的事件引用。
#
# 重放不创建新事件（只新建投递），引用的还是原事件的同一对象，因此
# “events 是否引用”就是充分的引用复核。

# 咨询锁标签（bigint），与 db.py DDL 串行锁 91247 区分。
ADV_LOCK_ORPHAN_GC = 912480


def advisory_key_for_sha(sha: str) -> int:
    """把 64 位 hex 摘要映射到 Postgres bigint 咨询锁键（取前 15 个 hex）。"""
    return int(sha[:15], 16)


async def get_payload_status(
    conn: asyncpg.Connection, sha: str
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT sha256, object_key, size_bytes, status, created_at, updated_at,
               committed_at
        FROM event_payloads WHERE sha256 = $1
        """,
        sha,
    )


async def count_payload_references(conn: asyncpg.Connection, sha: str) -> int:
    """事件对某载荷对象的引用数（GC 引用复核的唯一权威来源）。"""
    return await conn.fetchval(
        "SELECT COUNT(*) FROM events WHERE payload_sha256 = $1", sha
    )


# -- 在线迁移（JSONB -> 对象存储）-------------------------------------------------

async def start_or_adopt_payload_migration(conn: asyncpg.Connection) -> asyncpg.Record:
    """开始或接管一次载荷迁移运行（running/failed 记录存在则续跑）。"""
    for _attempt in range(2):
        async with conn.transaction():
            existing = await conn.fetchrow(
                """
                SELECT id, status, processed_count, last_event_id, last_error,
                       started_at, updated_at, finished_at
                FROM payload_migrations
                WHERE status IN ('running', 'failed')
                ORDER BY id
                LIMIT 1
                FOR UPDATE
                """
            )
            if existing is not None:
                await conn.execute(
                    """
                    UPDATE payload_migrations
                    SET status = 'running', last_error = NULL,
                        updated_at = now(), finished_at = NULL
                    WHERE id = $1
                    """,
                    existing["id"],
                )
                return existing
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO payload_migrations (status)
                    VALUES ('running')
                    RETURNING id, status, processed_count, last_event_id, last_error,
                              started_at, updated_at, finished_at
                    """
                )
                return row
            except asyncpg.UniqueViolationError:
                continue
    raise RuntimeError("无法创建或接管载荷迁移运行（并发冲突）")


async def fetch_legacy_payload_batch(
    conn: asyncpg.Connection, last_id: int, limit: int
) -> list[asyncpg.Record]:
    """取一批仍只有 JSONB、未回填内容地址的事件（FOR UPDATE SKIP LOCKED）。"""
    rows = await conn.fetch(
        """
        SELECT id, payload, payload_sha256
        FROM events
        WHERE id > $1 AND payload_sha256 IS NULL
        ORDER BY id
        LIMIT $2
        FOR UPDATE SKIP LOCKED
        """,
        last_id,
        limit,
    )
    return list(rows)


async def attach_event_payload(
    conn: asyncpg.Connection, event_id: int, sha: str
) -> None:
    """把已上传对象的摘要回填到事件（同事务要求对象目录已 committed）。"""
    await conn.execute(
        "UPDATE events SET payload_sha256 = $2 WHERE id = $1", event_id, sha
    )


async def ensure_payload_committed(
    conn: asyncpg.Connection,
    sha: str,
    object_key: str,
    size_bytes: int,
) -> None:
    """迁移用：upsert 目录行并直接置 committed（对象已由调用方上传）。"""
    await conn.execute(
        """
        INSERT INTO event_payloads
            (sha256, object_key, size_bytes, status, committed_at)
        VALUES ($1, $2, $3, 'committed', now())
        ON CONFLICT (sha256) DO UPDATE
            SET status = 'committed',
                committed_at = COALESCE(event_payloads.committed_at, now()),
                updated_at = now()
        """,
        sha,
        object_key,
        size_bytes,
    )


async def clear_event_jsonb(conn: asyncpg.Connection, event_id: int) -> None:
    """双读切换后释放某事件的 JSONB 副本（权威数据在对象存储）。"""
    await conn.execute(
        "UPDATE events SET payload = NULL WHERE id = $1 AND payload_sha256 IS NOT NULL",
        event_id,
    )


async def update_payload_migration_progress(
    conn: asyncpg.Connection, migration_id: int, processed: int, last_event_id: int
) -> None:
    await conn.execute(
        """
        UPDATE payload_migrations
        SET processed_count = processed_count + $2,
            last_event_id = GREATEST(last_event_id, $3),
            updated_at = now()
        WHERE id = $1
        """,
        migration_id,
        processed,
        last_event_id,
    )


async def finish_payload_migration(
    conn: asyncpg.Connection, status: str, error: str | None = None
) -> None:
    await conn.execute(
        """
        UPDATE payload_migrations
        SET status = $1, last_error = $2, updated_at = now(), finished_at = now()
        WHERE id = (
            SELECT id FROM payload_migrations
            WHERE status IN ('running', 'failed')
            ORDER BY id DESC LIMIT 1
        )
        """,
        status,
        error,
    )


async def list_payload_migrations(
    conn: asyncpg.Connection, limit: int = 10
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id, status, processed_count, last_event_id, last_error,
               started_at, updated_at, finished_at
        FROM payload_migrations
        ORDER BY id DESC
        LIMIT $1
        """,
        limit,
    )
    return list(rows)


async def count_legacy_payload_events(conn: asyncpg.Connection) -> int:
    """仍未回填内容地址的旧事件数（迁移进度）。"""
    return await conn.fetchval(
        "SELECT COUNT(*) FROM events WHERE payload_sha256 IS NULL"
    )


async def count_dual_copy_events(conn: asyncpg.Connection) -> int:
    """同时保留 JSONB 副本的事件数（切换/回收进度）。"""
    return await conn.fetchval(
        "SELECT COUNT(*) FROM events WHERE payload_sha256 IS NOT NULL AND payload IS NOT NULL"
    )


async def count_committed_payloads(conn: asyncpg.Connection) -> int:
    return await conn.fetchval(
        "SELECT COUNT(*) FROM event_payloads WHERE status = 'committed'"
    )


async def count_uploading_payloads(conn: asyncpg.Connection) -> int:
    return await conn.fetchval(
        "SELECT COUNT(*) FROM event_payloads WHERE status = 'uploading'"
    )


# -- 垃圾回收 ---------------------------------------------------------------------

async def fetch_abandoned_uploads(
    conn: asyncpg.Connection, stale_before, limit: int
) -> list[asyncpg.Record]:
    """宽限期后仍 uploading、且当前无事件引用的目录行（行锁，跳过被锁行）。

    无引用复核必须与删除决策同事务；updated_at 只在阶段 1 插入/状态推进时
    变化，并发提交的幂等接管不会刷新它，因此宽限期语义稳定。
    """
    rows = await conn.fetch(
        """
        SELECT p.sha256, p.object_key, p.size_bytes, p.updated_at
        FROM event_payloads p
        WHERE p.status = 'uploading'
          AND p.updated_at < $1
          AND NOT EXISTS (
              SELECT 1 FROM events e WHERE e.payload_sha256 = p.sha256
          )
        ORDER BY p.updated_at
        LIMIT $2
        FOR UPDATE OF p SKIP LOCKED
        """,
        stale_before,
        limit,
    )
    return list(rows)


async def delete_payload_row(conn: asyncpg.Connection, sha: str) -> None:
    """删除无引用的 uploading 目录行（仅 GC abandoned 分支调用）。"""
    await conn.execute(
        """
        DELETE FROM event_payloads
        WHERE sha256 = $1 AND status = 'uploading'
          AND NOT EXISTS (SELECT 1 FROM events WHERE payload_sha256 = $1)
        """,
        sha,
    )


async def register_orphan_claim(
    conn: asyncpg.Connection,
    sha: str,
    object_key: str,
    reason: str,
    delete_due_at,
) -> str:
    """GC 阶段一：登记删除凭证（幂等）。

    必须在持有按 sha 派生的事务级咨询锁时调用（与提交协议阶段 1 的
    “无目录行”分支互斥）。登记前复核：目录中已出现该 sha（committed 或
    uploading）则取消/跳过；已存在凭证则沿用其状态。
    返回登记后的状态：registered / delete_due / cancelled。
    """
    existing_meta = await conn.fetchrow(
        "SELECT status, object_key FROM event_payloads WHERE sha256 = $1", sha
    )
    if existing_meta is not None:
        # 对象已被提交或正在提交：若此前登记过凭证则标记取消。
        await conn.execute(
            "UPDATE payload_gc_claims SET status = 'cancelled', finished_at = now() "
            "WHERE sha256 = $1 AND status IN ('registered', 'delete_due')",
            sha,
        )
        return "cancelled"
    row = await conn.fetchrow(
        """
        INSERT INTO payload_gc_claims
            (sha256, object_key, reason, status, delete_due_at,
             finished_at, last_error)
        VALUES ($1, $2, $3, 'registered', $4, NULL, NULL)
        ON CONFLICT (sha256) DO UPDATE
            SET object_key = EXCLUDED.object_key,
                reason = EXCLUDED.reason,
                status = 'registered',
                delete_due_at = EXCLUDED.delete_due_at,
                finished_at = NULL,
                last_error = NULL
        RETURNING status
        """,
        sha,
        object_key,
        reason,
        delete_due_at,
    )
    return row["status"]


async def fetch_due_claims(conn: asyncpg.Connection, now, limit: int) -> list[asyncpg.Record]:
    """取到了宽限期、等待阶段二删除的凭证（行锁）。"""
    return list(
        await conn.fetch(
            """
            SELECT sha256, object_key, reason, registered_at, delete_due_at
            FROM payload_gc_claims
            WHERE status = 'registered' AND delete_due_at <= $1
            ORDER BY delete_due_at
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            """,
            now,
            limit,
        )
    )


async def recheck_claim_removable(conn: asyncpg.Connection, sha: str) -> bool:
    """删除前最终引用复核：目录必须完全无行且无事件引用。

    - committed 行：对象在服役，绝不可删；
    - uploading 行：存在（可能是刚刚发生的）上传意图——提交协议阶段 3 会在
      同一把咨询锁下复核对象并按需重传，因此这里也判定不可删并取消凭证
      （若该意图最终被放弃，宽限期后会以 abandoned_upload 重新登记回收）；
    - 任何 events 引用：不可删（死信重放只新建投递，引用不变，故事件引用
      是充分复核）。
    """
    meta = await conn.fetchrow(
        "SELECT status FROM event_payloads WHERE sha256 = $1", sha
    )
    if meta is not None:
        return False
    refs = await conn.fetchval(
        "SELECT COUNT(*) FROM events WHERE payload_sha256 = $1", sha
    )
    return refs == 0


async def mark_claim_deleted(conn: asyncpg.Connection, sha: str) -> None:
    await conn.execute(
        """
        UPDATE payload_gc_claims
        SET status = 'deleted', finished_at = now(), last_error = NULL
        WHERE sha256 = $1
        """,
        sha,
    )


async def mark_claim_cancelled(conn: asyncpg.Connection, sha: str) -> None:
    await conn.execute(
        """
        UPDATE payload_gc_claims
        SET status = 'cancelled', finished_at = now()
        WHERE sha256 = $1 AND status IN ('registered', 'delete_due')
        """,
        sha,
    )


async def mark_claim_error(conn: asyncpg.Connection, sha: str, error: str) -> None:
    await conn.execute(
        "UPDATE payload_gc_claims SET last_error = $2 WHERE sha256 = $1",
        sha,
        error[:500],
    )


async def list_gc_claims(
    conn: asyncpg.Connection, status: str | None = None, limit: int = 50
) -> list[asyncpg.Record]:
    if status is None:
        rows = await conn.fetch(
            """
            SELECT sha256, object_key, reason, status, registered_at, delete_due_at,
                   finished_at, last_error
            FROM payload_gc_claims ORDER BY registered_at DESC LIMIT $1
            """,
            limit,
        )
    else:
        rows = await conn.fetch(
            """
            SELECT sha256, object_key, reason, status, registered_at, delete_due_at,
                   finished_at, last_error
            FROM payload_gc_claims WHERE status = $2
            ORDER BY registered_at DESC LIMIT $1
            """,
            limit,
            status,
        )
    return list(rows)


async def count_gc_claims(conn: asyncpg.Connection) -> dict[str, int]:
    rows = await conn.fetch(
        """
        SELECT status, COUNT(*) AS n
        FROM payload_gc_claims GROUP BY status
        """
    )
    counts = {r["status"]: int(r["n"]) for r in rows}
    return {
        "registered": counts.get("registered", 0),
        "delete_due": counts.get("delete_due", 0),
        "deleted": counts.get("deleted", 0),
        "cancelled": counts.get("cancelled", 0),
    }
