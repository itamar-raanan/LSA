from lsa.services.agent_packages import AGENT_VERSION, native_agent_packages


def test_native_release_artifacts_are_discovered_with_audit_only_metadata(tmp_path, monkeypatch):
    debian = tmp_path / f"lsa-agent_{AGENT_VERSION}_all.deb"
    rpm = tmp_path / f"lsa-agent-{AGENT_VERSION}-1.noarch.rpm"
    debian.write_bytes(b"!<arch>\nexample-deb")
    rpm.write_bytes(b"\xed\xab\xee\xdbexample-rpm")
    monkeypatch.setenv("LSA_AGENT_PACKAGE_DIR", str(tmp_path))
    native_agent_packages.cache_clear()
    try:
        packages = native_agent_packages()
        assert [package.package_id for package in packages] == ["linux-deb", "linux-rpm"]
        assert [package.package_format for package in packages] == ["deb", "rpm"]
        assert all(package.version == AGENT_VERSION for package in packages)
        assert all(package.release_channel == "stable" for package in packages)
        assert all(package.audit_only for package in packages)
        assert all(len(package.sha256) == 64 for package in packages)
    finally:
        native_agent_packages.cache_clear()
