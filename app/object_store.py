"""S3 兼容对象存储客户端（MinIO / AWS S3 / 任何 S3 协议端点）。

用 boto3 的同步客户端在线程池中执行（`asyncio.to_thread`），避免引入事件循环
专用依赖；接口全部是 async，供 API 与 Worker 直接 await。

内容寻址约定（见 app/payload_object.py）：

- key 为 `payloads/<sha前2位>/<sha64>`；
- 对象不可变：put 幂等，同 key 已存在且字节一致即直接复用，绝不覆盖；
- 每次写入带 `Content-Type: application/json` 与自定义元数据
  `x-amz-meta-sha256 / x-amz-meta-kind`；
- 读取时校验：对象不存在抛 ObjectNotFound；长度/元数据可由调用方在 Worker
  取载荷路径上再做摘要复核（见 repository.fetch_event_payload_for_delivery）。

崩溃语义：put_object 成功但数据库尚未提交时，S3 中只可能多出“孤儿对象”，
永远不会出现数据库引用了不存在对象的情况（提交状态机先传对象再提交引用，
见 repository.commit_event_payload 与 app/objadmin.py 的 GC）。
"""
from __future__ import annotations

import asyncio
import logging

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.config import settings
from app.payload_object import (
    META_KIND,
    META_KIND_VALUE,
    META_SHA256,
    OBJECT_CONTENT_TYPE,
)

log = logging.getLogger("webhook.objectstore")


class ObjectStoreError(Exception):
    """对象存储不可用或读写失败（调用方按 503/投递失败处理）。"""

    def __init__(self, message: str, *, code: str = "object_store_error"):
        super().__init__(message)
        self.code = code


class ObjectNotFound(ObjectStoreError):
    """引用的对象在桶中不存在（可能被外部误删或 GC 竞态）。"""

    def __init__(self, key: str):
        super().__init__(f"对象不存在: {key}", code="object_not_found")
        self.key = key


class ObjectContentMismatch(ObjectStoreError):
    """同 key 已存在的对象与本次内容地址不一致（不可变对象被破坏）。"""

    def __init__(self, key: str):
        super().__init__(
            f"对象 {key} 已存在但内容与内容地址不一致（不可变对象被破坏）",
            code="object_content_mismatch",
        )
        self.key = key


class ObjectStore:
    def __init__(
        self,
        endpoint_url: str,
        bucket: str,
        access_key: str,
        secret_key: str,
        region: str,
        *,
        force_path_style: bool = True,
    ) -> None:
        self.bucket = bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            # MinIO 等自建端点必须 path-style；AWS 虚拟主机风格也兼容 path-style。
            config=Config(
                s3={"addressing_style": "path" if force_path_style else "auto"},
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=15,
            ),
        )

    # -- 生命周期 -----------------------------------------------------------------

    def ensure_bucket_sync(self) -> None:
        """确保桶存在（不存在则创建）。启动期同步调用，容忍短暂未就绪。"""
        try:
            self._client.head_bucket(Bucket=self.bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            # 404/NoSuchBucket：需要创建；403（某些公开端点）交由 create 再报错。
            if code not in ("404", "NoSuchBucket", "NotFound"):
                raise ObjectStoreError(
                    f"无法访问对象桶 {self.bucket!r}: {exc}",
                    code="bucket_unavailable",
                ) from exc
        try:
            self._client.create_bucket(Bucket=self.bucket)
            log.info("已创建对象桶 %s", self.bucket)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise ObjectStoreError(
                    f"创建对象桶 {self.bucket!r} 失败: {exc}",
                    code="bucket_create_failed",
                ) from exc

    # -- 读 -----------------------------------------------------------------------

    def get_object_sync(self, key: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404", "NotFound"):
                raise ObjectNotFound(key) from exc
            raise ObjectStoreError(f"读取对象 {key} 失败: {exc}") from exc
        data = resp["Body"].read()
        return data

    def head_object_sync(self, key: str) -> dict | None:
        """返回对象元数据（ContentLength/Metadata）；不存在返回 None。"""
        try:
            resp = self._client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("404", "NotFound", "NoSuchKey"):
                return None
            raise ObjectStoreError(f"查询对象 {key} 失败: {exc}") from exc
        return {
            "content_length": resp.get("ContentLength"),
            "metadata": resp.get("Metadata") or {},
        }

    # -- 写 -----------------------------------------------------------------------

    def put_payload_if_absent_sync(self, key: str, body: bytes, sha: str) -> None:
        """按内容地址幂等写入不可变对象。

        - 已存在：只做内容长度/元数据复核，不覆盖（任何并发提交的字节必然
          相同，因为 key 即规范化内容的 SHA-256）；
        - 不存在：写入并带 sha256/kind 元数据；
        - 已存在但内容长度异常：抛 ObjectContentMismatch，由上层拒绝提交。
        """
        existing = self.head_object_sync(key)
        if existing is not None:
            if existing["content_length"] != len(body):
                raise ObjectContentMismatch(key)
            # 元数据中的 sha256 若存在则必须一致（小写 hex）。
            meta_sha = (existing["metadata"] or {}).get(META_SHA256)
            if meta_sha and meta_sha.lower() != sha.lower():
                raise ObjectContentMismatch(key)
            return
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentType=OBJECT_CONTENT_TYPE,
                Metadata={META_SHA256: sha, META_KIND: META_KIND_VALUE},
            )
        except ClientError as exc:
            raise ObjectStoreError(f"写入对象 {key} 失败: {exc}") from exc

    def delete_object_sync(self, key: str) -> None:
        """删除对象（GC 两阶段删除阶段调用；键不存在视为成功）。"""
        try:
            self._client.delete_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            raise ObjectStoreError(f"删除对象 {key} 失败: {exc}") from exc

    def list_object_keys_sync(self, prefix: str = "", limit: int = 1000) -> list[str]:
        """列出桶内对象 key（GC 扫描用；分页取至多 limit 个）。"""
        keys: list[str] = []
        kwargs: dict = {"Bucket": self.bucket, "MaxKeys": min(limit, 1000)}
        if prefix:
            kwargs["Prefix"] = prefix
        while len(keys) < limit:
            try:
                resp = self._client.list_objects_v2(**kwargs)
            except ClientError as exc:
                raise ObjectStoreError(f"列举对象失败: {exc}") from exc
            for item in resp.get("Contents", []):
                keys.append(item["Key"])
                if len(keys) >= limit:
                    return keys
            if not resp.get("IsTruncated"):
                break
            kwargs["ContinuationToken"] = resp["NextContinuationToken"]
        return keys

    # -- async 包装（在线程池中跑同步 boto3 调用）--------------------------------

    async def ensure_bucket(self, *, retries: int = 30, delay: float = 1.0) -> None:
        last: Exception | None = None
        for attempt in range(retries):
            try:
                await asyncio.to_thread(self.ensure_bucket_sync)
                return
            except ObjectStoreError as exc:
                last = exc
                log.info(
                    "等待对象存储就绪（%s/%s）: %s", attempt + 1, retries, exc
                )
                await asyncio.sleep(delay)
        raise ObjectStoreError(
            f"对象存储在 {retries} 次尝试后仍不可用: {last}",
            code="object_store_unavailable",
        )

    async def get_object(self, key: str) -> bytes:
        return await asyncio.to_thread(self.get_object_sync, key)

    async def put_payload_if_absent(self, key: str, body: bytes, sha: str) -> None:
        await asyncio.to_thread(self.put_payload_if_absent_sync, key, body, sha)

    async def delete_object(self, key: str) -> None:
        await asyncio.to_thread(self.delete_object_sync, key)

    async def list_object_keys(
        self, prefix: str = "", limit: int = 1000
    ) -> list[str]:
        return await asyncio.to_thread(self.list_object_keys_sync, prefix, limit)


_store: ObjectStore | None = None


def get_object_store() -> ObjectStore:
    """进程级单例；惰性创建（配置非法直接报错）。"""
    global _store
    if _store is None:
        _store = ObjectStore(
            endpoint_url=settings.s3_endpoint_url,
            bucket=settings.s3_bucket,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
            region=settings.s3_region,
            force_path_style=settings.s3_force_path_style,
        )
    return _store


async def init_object_store(*, ensure: bool = True) -> ObjectStore:
    store = get_object_store()
    if ensure:
        await store.ensure_bucket()
    return store


def reset_object_store_cache() -> None:
    """清空进程内缓存（测试用）。"""
    global _store
    _store = None
