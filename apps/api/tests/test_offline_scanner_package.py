import hashlib
import io
import zipfile


def _login(client) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@lsa.local", "password": "test-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_authenticated_user_can_download_a_complete_offline_scanner(client):
    headers = _login(client)

    metadata = client.get("/api/v1/offline-scanner-package", headers=headers)
    assert metadata.status_code == 200
    package = metadata.json()
    assert package["version"] == "0.6.1"
    assert package["filename"] == "lsa-offline-scanner-0.6.1.zip"
    assert package["audit_only"] is True

    downloaded = client.get("/api/v1/offline-scanner-package/download", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.headers["content-disposition"] == (
        'attachment; filename="lsa-offline-scanner-0.6.1.zip"'
    )
    assert hashlib.sha256(downloaded.content).hexdigest() == package["sha256"]
    assert downloaded.headers["x-lsa-scanner-sha256"] == package["sha256"]

    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        root = "lsa-offline-scanner-0.6.1"
        names = set(archive.namelist())
        assert f"{root}/README.md" in names
        assert f"{root}/inventory.ini" in names
        assert f"{root}/run-offline.sh" in names
        assert f"{root}/checksums.sha256" in names
        assert f"{root}/scanner/playbooks/scan.yml" in names
        assert f"{root}/scanner/scripts/generate_signing_key.py" in names
        assert f"{root}/scanner/roles/lsa_report/tasks/main.yml" in names
        assert not any("/__pycache__/" in name or "/tests/" in name for name in names)

        readme = archive.read(f"{root}/README.md").decode()
        assert "Step 1 — Install The Ansible Requirement" in readme
        assert "Do not extract or modify that ZIP" in readme
        runner_mode = archive.getinfo(f"{root}/run-offline.sh").external_attr >> 16
        inventory_mode = archive.getinfo(f"{root}/inventory.ini").external_attr >> 16
        assert runner_mode & 0o777 == 0o755
        assert inventory_mode & 0o777 == 0o600

        declared = archive.read(f"{root}/checksums.sha256").decode().splitlines()
        for entry in declared:
            expected, relative = entry.split("  ", maxsplit=1)
            assert hashlib.sha256(archive.read(f"{root}/{relative}")).hexdigest() == expected


def test_offline_scanner_download_requires_a_session(client):
    response = client.get("/api/v1/offline-scanner-package/download")
    assert response.status_code == 401
