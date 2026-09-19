"""运行配置：全部来自环境变量，默认值可直接在 docker compose 中运行。"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://webhook:webhook@db:5432/webhooks"
    )
    # 租约时长：in_flight 投递超过该时间未心跳/未结算即可被其他 Worker 接管
    lease_seconds: int = _get_int("LEASE_SECONDS", 30)
    http_timeout_seconds: float = _get_float("HTTP_TIMEOUT_SECONDS", 10)
    worker_poll_seconds: float = _get_float("WORKER_POLL_SECONDS", 1)
    # 失败策略：共尝试 max_attempts 次；第 n 次失败后等待 base*2^(n-1)（封顶 cap）
    max_attempts: int = _get_int("MAX_ATTEMPTS", 6)
    backoff_base_seconds: float = _get_float("BACKOFF_BASE_SECONDS", 5)
    backoff_cap_seconds: float = _get_float("BACKOFF_CAP_SECONDS", 300)
    # 本地回调接收器
    receiver_secret: str = os.getenv("RECEIVER_SECRET", "")
    receiver_timestamp_tolerance: int = _get_int(
        "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS", 300
    )
    # 出站目标安全策略（SSRF 防护）
    # 精确主机名白名单（逗号分隔，大小写不敏感）；命中即放行其全部解析地址
    allowed_hosts: str = os.getenv("WEBHOOK_ALLOWED_HOSTS", "")
    # CIDR/IP 白名单（逗号分隔）；地址落入即放行，即使属于默认阻止类别
    allowed_cidrs: str = os.getenv("WEBHOOK_ALLOWED_CIDRS", "")
    # Worker 跟随重定向的最大跳数（每一跳都重新执行同一策略）
    max_redirects: int = _get_int("WEBHOOK_MAX_REDIRECTS", 5)
    # 订阅 HMAC 密钥信封加密的本地密钥环（主密钥不落数据库）：
    # WEBHOOK_KEYRING_JSON 非空时优先，否则读 WEBHOOK_KEYRING_FILE 指向的 JSON 文件；
    # 两者都为空表示未配置（新配置版本无法写入，已加密版本无法投递）。
    keyring_json: str = os.getenv("WEBHOOK_KEYRING_JSON", "")
    keyring_file: str = os.getenv("WEBHOOK_KEYRING_FILE", "")


settings = Settings()
