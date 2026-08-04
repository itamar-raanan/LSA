from scanner.library.lsa_application_inventory import parse_dpkg, parse_rpm, parse_services


def test_parse_dpkg_keeps_only_installed_packages():
    applications = parse_dpkg(
        "openssl\t3.0.14-1\tamd64\tii \tDebian OpenSSL Team\topenssl\t3.0.14-1\n"
        "old-package\t1.0\tamd64\trc \tDebian QA Group\told-package\t1.0\n",
        distribution="debian",
        distribution_version="13",
    )
    assert applications == [
        {
            "kind": "package",
            "name": "openssl",
            "version": "3.0.14-1",
            "architecture": "amd64",
            "source": "dpkg",
            "source_package": "openssl",
            "source_version": "3.0.14-1",
            "purl": "pkg:deb/debian/openssl@3.0.14-1?arch=amd64&distro=debian-13",
            "publisher": "Debian OpenSSL Team",
            "status": "installed",
            "enabled": None,
            "running": None,
        }
    ]


def test_parse_dpkg_accepts_legacy_query_shape():
    applications = parse_dpkg("curl\t8.10.1-1\tamd64\tii \tDebian Curl Maintainers\n")

    assert applications[0]["source_package"] == "curl"
    assert applications[0]["source_version"] == "8.10.1-1"
    assert applications[0]["purl"] == "pkg:deb/debian/curl@8.10.1-1?arch=amd64"


def test_parse_rpm_preserves_vendor_and_architecture():
    applications = parse_rpm(
        "openssl-libs\t0:3.2.2-6.el9\tx86_64\tRed Hat, Inc.\topenssl-3.2.2-6.el9.src.rpm\n",
        distribution="rhel",
        distribution_version="9.4",
    )
    assert applications[0]["publisher"] == "Red Hat, Inc."
    assert applications[0]["version"] == "0:3.2.2-6.el9"
    assert applications[0]["architecture"] == "x86_64"
    assert applications[0]["source_package"] == "openssl"
    assert applications[0]["source_version"] == "3.2.2-6.el9"
    assert applications[0]["purl"] == (
        "pkg:rpm/rhel/openssl-libs@0%3A3.2.2-6.el9?arch=x86_64&distro=rhel-9.4"
    )


def test_parse_services_combines_boot_and_runtime_state():
    applications = parse_services(
        "chronyd.service disabled enabled\noneshot.service static -\nsshd.service enabled enabled\n",
        "oneshot.service loaded active exited One-shot initializer\nsshd.service loaded active running OpenSSH server daemon\n",
    )
    assert applications[0]["name"] == "chronyd.service"
    assert applications[0]["enabled"] is False
    assert applications[0]["running"] is False
    assert applications[1]["name"] == "oneshot.service"
    assert applications[1]["status"] == "active"
    assert applications[1]["running"] is False
    assert applications[2]["name"] == "sshd.service"
    assert applications[2]["enabled"] is True
    assert applications[2]["running"] is True
    assert applications[2]["description"] == "OpenSSH server daemon"
