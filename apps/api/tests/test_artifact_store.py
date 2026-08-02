from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from lsa.services.artifacts import ArtifactStoreError, FilesystemArtifactStore, S3ArtifactStore


def test_filesystem_store_rejects_path_escape(tmp_path: Path):
    store = FilesystemArtifactStore(str(tmp_path))
    with pytest.raises(ArtifactStoreError, match="Unsafe artifact object key"):
        store.put("../outside.zip", b"evidence", "application/zip", None)


def test_s3_store_tracks_and_deletes_exact_locked_version():
    store = object.__new__(S3ArtifactStore)
    store.bucket = "lsa-evidence"
    store.server_side_encryption = "AES256"
    store.client = Mock()
    store.client.put_object.return_value = {"VersionId": "version-7"}
    retention = datetime.now(UTC) + timedelta(days=365)

    version = store.put("tenant/report/evidence.zip", b"evidence", "application/zip", retention)

    assert version == "version-7"
    put = store.client.put_object.call_args.kwargs
    assert put["ObjectLockMode"] == "COMPLIANCE"
    assert put["ObjectLockRetainUntilDate"] == retention
    assert put["ServerSideEncryption"] == "AES256"
    store.delete("tenant/report/evidence.zip", version)
    store.client.delete_object.assert_called_once_with(
        Bucket="lsa-evidence",
        Key="tenant/report/evidence.zip",
        VersionId="version-7",
    )


def test_s3_store_can_defer_encryption_to_private_storage_layer():
    store = object.__new__(S3ArtifactStore)
    store.bucket = "lsa-evidence"
    store.server_side_encryption = "none"
    store.client = Mock()
    store.client.put_object.return_value = {"VersionId": "version-8"}

    store.put("tenant/report/evidence.zip", b"evidence", "application/zip", None)

    assert "ServerSideEncryption" not in store.client.put_object.call_args.kwargs
