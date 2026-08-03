from scanner.library.lsa_application_inventory import parse_dpkg, parse_rpm, parse_services


def test_parse_dpkg_keeps_only_installed_packages():
    applications = parse_dpkg(
        "openssl\t3.0.14-1\tamd64\tii \tDebian OpenSSL Team\n"
        "old-package\t1.0\tamd64\trc \tDebian QA Group\n"
    )
    assert applications == [
        {
            "kind": "package",
            "name": "openssl",
            "version": "3.0.14-1",
            "architecture": "amd64",
            "source": "dpkg",
            "publisher": "Debian OpenSSL Team",
            "status": "installed",
            "enabled": None,
            "running": None,
        }
    ]


def test_parse_rpm_preserves_vendor_and_architecture():
    applications = parse_rpm("openssl-libs\t0:3.2.2-6.el9\tx86_64\tRed Hat, Inc.\n")
    assert applications[0]["publisher"] == "Red Hat, Inc."
    assert applications[0]["version"] == "0:3.2.2-6.el9"
    assert applications[0]["architecture"] == "x86_64"


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
