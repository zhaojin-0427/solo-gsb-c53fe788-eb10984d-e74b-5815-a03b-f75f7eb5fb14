"""数据库连接池与表结构初始化。"""
from __future__ import annotations

import asyncio
import json
import logging

import asyncpg

from app.config import settings

log = logging.getLogger("webhook.db")

_pool: asyncpg.Pool | None = None


async def _init_connection(conn: asyncpg.Connection) -> None:
    """让 jsonb 直接以 Python dict 进出。"""
    await conn.set_type_codec(
        "json",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )

# 订阅配置版本化（无损切换）：
# - subscriptions 保留身份（id/source）与启用状态，current_revision 指向当前版本；
# - subscription_versions 不可变保存每个版本的 target_url / HMAC 密钥 / 重试参数，
#   revision 从 1 起单调递增；发布新版本只追加，不改旧版本；
# - deliveries.config_version_id 固化该投递实际使用的版本：边界前创建的投递
#   （含其后续全部重试、接管、死信重放）永远钉在旧版本上，边界后创建的才用新版本；
# - created_at 即该版本成为当前版本（切换边界）的时刻；被新版本取代后由
#   superseded_at 记录其边界结束时刻。
#
# HMAC 密钥信封加密（见 app/envelope.py、app/keyring.py）：
# - 新版本的密钥以随机 DEK 经 AES-256-GCM 加密（AAD 绑定 subscription_id +
#   version_id），DEK 再由本地密钥环主密钥包裹；数据库只存
#   secret_ciphertext / secret_dek_wrapped / secret_key_id，明文不落盘；
# - secret 明文列仅用于迁移前的旧记录（迁移期间新旧格式均可读取），
#   迁移/新写入后该列置空；subscriptions.secret 冗余列同样不再写明文；
# - key_rotations 持久化主密钥轮换进度：轮换只重包裹 DEK（不动密钥密文），
#   可断点续跑、可并发执行。


def _schema_statements(
    max_attempts: int, backoff_base: float, backoff_cap: float
) -> list[str]:
    """返回建表/迁移语句。

    重试参数的全局默认值仅用于“旧库升级”时回填现存订阅的初始版本；新订阅的
    初始版本参数在 repository 层创建订阅时显式写入。
    """
    return [
        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            id               BIGSERIAL PRIMARY KEY,
            source           TEXT NOT NULL,
            target_url       TEXT NOT NULL,
            secret           TEXT NOT NULL,
            active           BOOLEAN NOT NULL DEFAULT TRUE,
            current_revision INTEGER NOT NULL DEFAULT 1,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (source, target_url)
        )
        """,
        # 旧库升级：补 current_revision 列（先可空，回填后再置 NOT NULL）
        """
        ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS current_revision INTEGER
        """,
        """
        CREATE TABLE IF NOT EXISTS subscription_versions (
            id                  BIGSERIAL PRIMARY KEY,
            subscription_id     BIGINT NOT NULL REFERENCES subscriptions(id),
            revision            INTEGER NOT NULL,
            target_url          TEXT NOT NULL,
            secret              TEXT NOT NULL,
            max_attempts        INTEGER NOT NULL,
            backoff_base_seconds   DOUBLE PRECISION NOT NULL,
            backoff_cap_seconds    DOUBLE PRECISION NOT NULL,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
            superseded_at       TIMESTAMPTZ,
            UNIQUE (subscription_id, revision)
        )
        """,
        # 信封加密列（旧库升级幂等补充）：
        # secret_ciphertext 非空即信封格式；为空则 secret 列仍是明文（待迁移）。
        """
        ALTER TABLE subscription_versions
            ADD COLUMN IF NOT EXISTS secret_ciphertext BYTEA
        """,
        """
        ALTER TABLE subscription_versions
            ADD COLUMN IF NOT EXISTS secret_dek_wrapped BYTEA
        """,
        """
        ALTER TABLE subscription_versions
            ADD COLUMN IF NOT EXISTS secret_key_id TEXT
        """,
        # 轮换扫描：按 key_id 找待重包裹的记录
        """
        CREATE INDEX IF NOT EXISTS idx_sub_versions_key_id
            ON subscription_versions (secret_key_id)
        """,
        # 迁移扫描：待加密的明文版本
        """
        CREATE INDEX IF NOT EXISTS idx_sub_versions_plaintext
            ON subscription_versions (id)
            WHERE secret_ciphertext IS NULL
        """,
        # 主密钥轮换进度（持久化，支持断点续跑与失败恢复）
        """
        CREATE TABLE IF NOT EXISTS key_rotations (
            id              BIGSERIAL PRIMARY KEY,
            old_key_id      TEXT NOT NULL DEFAULT '',
            new_key_id      TEXT NOT NULL,
            status          TEXT NOT NULL CHECK (status IN
                                ('running', 'completed', 'failed')),
            processed_count BIGINT NOT NULL DEFAULT 0,
            last_version_id BIGINT NOT NULL DEFAULT 0,
            last_error      TEXT,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            finished_at     TIMESTAMPTZ
        )
        """,
        # 同一目标 key_id 至多一条进行中的轮换（并发轮换进程会接管同一运行）
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_key_rotations_active
            ON key_rotations (new_key_id) WHERE status = 'running'
        """,
        """
        CREATE TABLE IF NOT EXISTS events (
            id          BIGSERIAL PRIMARY KEY,
            source      TEXT NOT NULL,
            event_id    TEXT NOT NULL,
            payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (source, event_id)
        )
        """,
        # 投递链：重放时复用同一 chain_id，chain_seq 从 1 递增；链内严格有序
        "CREATE SEQUENCE IF NOT EXISTS delivery_chain_seq START 1",
        "CREATE SEQUENCE IF NOT EXISTS delivery_seq_global START 1",
        """
        CREATE TABLE IF NOT EXISTS deliveries (
            id                 BIGSERIAL PRIMARY KEY,
            event_id_fk        BIGINT NOT NULL REFERENCES events(id),
            subscription_id    BIGINT NOT NULL REFERENCES subscriptions(id),
            config_version_id  BIGINT NOT NULL REFERENCES subscription_versions(id),
            chain_id           BIGINT NOT NULL,
            chain_seq          INTEGER NOT NULL,
            seq                BIGINT NOT NULL DEFAULT nextval('delivery_seq_global'),
            status             TEXT NOT NULL CHECK (status IN
                                 ('pending', 'in_flight', 'succeeded', 'dead_lettered')),
            attempts_made      INTEGER NOT NULL DEFAULT 0,
            not_before         TIMESTAMPTZ NOT NULL DEFAULT now(),
            leased_at          TIMESTAMPTZ,
            lease_expires_at   TIMESTAMPTZ,
            leased_by          TEXT,
            created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (subscription_id, chain_id, chain_seq)
        )
        """,
        # 旧库升级：deliveries 补 config_version_id（先可空，回填后再置 NOT NULL）
        """
        ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS config_version_id BIGINT
            REFERENCES subscription_versions(id)
        """,
        # 防止事件首次提交时为同一订阅重复建投递；重放（chain_seq>1）不受此约束。
        # 顺带移除早期版本的全量唯一索引（会阻止重放）。
        "DROP INDEX IF EXISTS uq_deliveries_event_sub",
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_deliveries_event_sub_initial
            ON deliveries (event_id_fk, subscription_id)
            WHERE chain_seq = 1
        """,
        # 顺序判断主索引：按订阅 + seq 找队首
        """
        CREATE INDEX IF NOT EXISTS idx_deliveries_sub_status_seq
            ON deliveries (subscription_id, status, seq)
        """,
        """
        CREATE TABLE IF NOT EXISTS delivery_attempts (
            id               BIGSERIAL PRIMARY KEY,
            delivery_id      BIGINT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
            attempt_number   INTEGER NOT NULL,
            worker_id        TEXT NOT NULL,
            started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            finished_at      TIMESTAMPTZ,
            outcome          TEXT NOT NULL CHECK (outcome IN
                                 ('success', 'http_error', 'network_error', 'timeout',
                                  'security_blocked', 'crypto_error')),
            http_status      INTEGER,
            response_excerpt TEXT,
            error_message    TEXT,
            leased_at        TIMESTAMPTZ,
            lease_expires_at TIMESTAMPTZ,
            UNIQUE (delivery_id, attempt_number)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_attempts_delivery
            ON delivery_attempts (delivery_id, attempt_number)
        """,
        # 旧库升级：放宽 delivery_attempts.outcome 的 CHECK，纳入 security_blocked
        # 与 crypto_error。旧约束名为 Postgres 自动命名
        # （delivery_attempts_outcome_check），存在则替换；新建库上面的
        # CREATE TABLE 已带新约束，DROP IF EXISTS 不会命中任何东西，
        # 随后 ADD CONSTRAINT 因约束已存在而跳过（DO 块守卫）。
        """
        ALTER TABLE delivery_attempts
            DROP CONSTRAINT IF EXISTS delivery_attempts_outcome_check
        """,
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'delivery_attempts'::regclass
                  AND conname = 'delivery_attempts_outcome_check'
            ) THEN
                ALTER TABLE delivery_attempts
                    ADD CONSTRAINT delivery_attempts_outcome_check
                    CHECK (outcome IN
                        ('success', 'http_error', 'network_error', 'timeout',
                         'security_blocked', 'crypto_error'));
            END IF;
        END$$
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_sub_versions_revision
            ON subscription_versions (subscription_id, revision)
        """,

        # ---- 旧库升级：把现存订阅回填为 revision 1（幂等）----
        # 版本参数使用全局默认（旧表行上本来就没有按订阅保存的重试参数）。
        f"""
        INSERT INTO subscription_versions
            (subscription_id, revision, target_url, secret,
             max_attempts, backoff_base_seconds, backoff_cap_seconds)
        SELECT s.id, 1, s.target_url, s.secret,
               {int(max_attempts)}, {float(backoff_base)}, {float(backoff_cap)}
        FROM subscriptions s
        WHERE NOT EXISTS (
            SELECT 1 FROM subscription_versions v
            WHERE v.subscription_id = s.id AND v.revision = 1
        )
        """,
        # 把历史投递钉到其订阅的 revision 1
        """
        UPDATE deliveries d
        SET config_version_id = v.id
        FROM subscription_versions v
        WHERE d.config_version_id IS NULL
          AND v.subscription_id = d.subscription_id
          AND v.revision = 1
        """,
        # 统一 current_revision（缺失则视为 1）
        """
        UPDATE subscriptions s
        SET current_revision = 1
        WHERE s.current_revision IS NULL
        """,
        """
        ALTER TABLE subscriptions ALTER COLUMN current_revision SET NOT NULL
        """,
        """
        ALTER TABLE deliveries ALTER COLUMN config_version_id SET NOT NULL
        """,
    ]


async def create_pool(dsn: str | None = None) -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool

    dsn = dsn or settings.database_url
    # 等待数据库就绪（compose 启动顺序下 postgres 可能尚未接受连接）
    last_error: Exception | None = None
    for attempt in range(60):
        try:
            pool = await asyncpg.create_pool(
                dsn,
                min_size=1,
                max_size=10,
                command_timeout=30,
                init=_init_connection,
            )
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            _pool = pool
            log.info("数据库连接池已建立")
            return pool
        except Exception as exc:  # noqa: BLE001 - 启动期需容忍数据库未就绪
            last_error = exc
            log.info("等待数据库就绪（%s/60）: %s", attempt + 1, exc)
            await asyncio.sleep(1)
    raise RuntimeError(f"无法连接数据库: {last_error}")


async def init_schema(conn: asyncpg.Connection) -> None:
    # 咨询锁串行化多进程（api + 多 worker）启动时的并发 DDL，
    # 避免 IF NOT EXISTS 在 pg_class 上的竞态冲突。
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(91247)")
        for statement in _schema_statements(
            settings.max_attempts,
            settings.backoff_base_seconds,
            settings.backoff_cap_seconds,
        ):
            await conn.execute(statement)
    log.info("数据库表结构已初始化")


async def init_db() -> asyncpg.Pool:
    pool = await create_pool()
    async with pool.acquire() as conn:
        await init_schema(conn)
    return pool


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("数据库连接池尚未初始化")
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
