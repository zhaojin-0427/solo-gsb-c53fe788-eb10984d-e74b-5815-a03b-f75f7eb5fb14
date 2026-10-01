"""FastAPI 入口。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import api
from app.db import close_pool, init_db
from app.keyring import get_keyring
from app.object_store import init_object_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # 确保载荷对象桶存在（等待本地 MinIO/S3 就绪，约 30 秒）。
    await init_object_store()
    # 启动时加载本地密钥环：配置非法直接启动失败（避免运行期才暴露）；
    # 未配置则降级为只读（写入接口 503），详见 app/keyring.py。
    get_keyring()
    yield
    await close_pool()


app = FastAPI(
    title="可靠 Webhook 投递服务",
    version="1.0.0",
    description=(
        "事件幂等提交、严格顺序投递、租约抢占、指数退避、死信重放。"
        "交互文档见 /docs。"
    ),
    lifespan=lifespan,
)

app.include_router(api.router)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    from app.config import settings as s

    return {
        "status": "ok",
        "payload_store_bucket": s.s3_bucket,
    }
