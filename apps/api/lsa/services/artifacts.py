import os
import uuid
import base64
import hashlib
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends

from lsa.config import Settings, get_settings


class ArtifactStoreError(RuntimeError):
    pass


class ArtifactNotFound(ArtifactStoreError):
    pass


class ArtifactStore(Protocol):
    def ensure_ready(self) -> None: ...

    def put(
        self,
        key: str,
        data: bytes,
        content_type: str,
        retention_until: datetime | None,
    ) -> str | None: ...

    def get(self, key: str, version_id: str | None = None) -> bytes: ...

    def delete(self, key: str, version_id: str | None = None) -> None: ...


def artifact_key(tenant_id: str, report_id: str) -> str:
    return f"tenants/{tenant_id}/reports/{report_id}/{uuid.uuid4()}.zip"


class FilesystemArtifactStore:
    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise ArtifactStoreError("Unsafe artifact object key")
        return path

    def ensure_ready(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if not os.access(self.root, os.R_OK | os.W_OK | os.X_OK):
            raise ArtifactStoreError("Artifact directory is not accessible")

    def put(
        self,
        key: str,
        data: bytes,
        content_type: str,
        retention_until: datetime | None,
    ) -> str | None:
        del content_type, retention_until
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ArtifactStoreError("Artifact object already exists") from exc
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
        return None

    def get(self, key: str, version_id: str | None = None) -> bytes:
        del version_id
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactNotFound("Artifact object is missing") from exc

    def delete(self, key: str, version_id: str | None = None) -> None:
        del version_id
        self._path(key).unlink(missing_ok=True)


class S3ArtifactStore:
    def __init__(self, settings: Settings) -> None:
        if not settings.s3_access_key or not settings.s3_secret_key:
            raise ArtifactStoreError("S3 artifact credentials are not configured")
        self.bucket = settings.s3_bucket
        self.region = settings.s3_region
        self.server_side_encryption = settings.s3_server_side_encryption
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            region_name=settings.s3_region,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
        )

    def ensure_ready(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if str(code) not in {"404", "NoSuchBucket", "NotFound"}:
                raise ArtifactStoreError("S3 evidence bucket is unavailable") from exc
            parameters = {"Bucket": self.bucket}
            if self.region != "us-east-1":
                parameters["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
            try:
                self.client.create_bucket(**parameters, ObjectLockEnabledForBucket=True)
            except (BotoCoreError, ClientError) as create_exc:
                raise ArtifactStoreError("S3 evidence bucket could not be created") from create_exc
        except BotoCoreError as exc:
            raise ArtifactStoreError("S3 evidence store is unavailable") from exc

    def put(
        self,
        key: str,
        data: bytes,
        content_type: str,
        retention_until: datetime | None,
    ) -> str | None:
        parameters = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type,
            "Metadata": {"lsa-immutable": "true"},
            # S3 Object Lock requires a transport Content-MD5 header. The vault's
            # security integrity check remains SHA-256 in report metadata.
            "ContentMD5": base64.b64encode(
                hashlib.md5(data, usedforsecurity=False).digest()
            ).decode(),
        }
        if self.server_side_encryption != "none":
            parameters["ServerSideEncryption"] = self.server_side_encryption
        if retention_until is not None:
            parameters.update(
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retention_until,
            )
        try:
            response = self.client.put_object(**parameters)
            return response.get("VersionId")
        except (BotoCoreError, ClientError) as exc:
            raise ArtifactStoreError("Evidence artifact could not be stored") from exc

    def get(self, key: str, version_id: str | None = None) -> bytes:
        parameters = {"Bucket": self.bucket, "Key": key}
        if version_id:
            parameters["VersionId"] = version_id
        try:
            response = self.client.get_object(**parameters)
            return response["Body"].read()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if str(code) in {"404", "NoSuchKey", "NotFound"}:
                raise ArtifactNotFound("Artifact object is missing") from exc
            raise ArtifactStoreError("Evidence artifact could not be read") from exc
        except BotoCoreError as exc:
            raise ArtifactStoreError("Evidence artifact could not be read") from exc

    def delete(self, key: str, version_id: str | None = None) -> None:
        parameters = {"Bucket": self.bucket, "Key": key}
        if version_id:
            parameters["VersionId"] = version_id
        try:
            self.client.delete_object(**parameters)
        except (BotoCoreError, ClientError) as exc:
            raise ArtifactStoreError("Evidence artifact could not be deleted") from exc


@lru_cache
def build_artifact_store(
    backend: str,
    root: str,
    endpoint: str | None,
    bucket: str,
    region: str,
    access_key: str | None,
    secret_key: str | None,
    server_side_encryption: str,
) -> ArtifactStore:
    settings = Settings(
        artifact_backend=backend,
        artifact_path=root,
        s3_endpoint_url=endpoint,
        s3_bucket=bucket,
        s3_region=region,
        s3_access_key=access_key,
        s3_secret_key=secret_key,
        s3_server_side_encryption=server_side_encryption,
    )
    if backend == "s3":
        return S3ArtifactStore(settings)
    return FilesystemArtifactStore(root)


def get_artifact_store(settings: Settings = Depends(get_settings)) -> ArtifactStore:
    return build_artifact_store(
        settings.artifact_backend,
        settings.artifact_path,
        settings.s3_endpoint_url,
        settings.s3_bucket,
        settings.s3_region,
        settings.s3_access_key,
        settings.s3_secret_key,
        settings.s3_server_side_encryption,
    )
