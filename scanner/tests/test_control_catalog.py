import re
from collections import Counter
from pathlib import Path

import yaml
from jinja2 import Environment


CIS_ROLE = Path("scanner/roles/cis_debian13_audit")
HEALTH_ROLE = Path("scanner/roles/linux_security_health")
REPORT_ROLE = Path("scanner/roles/lsa_report")
CANONICAL_CATEGORIES = {
    "accounts",
    "audit",
    "filesystem",
    "kernel",
    "logging",
    "mandatory_access",
    "network",
    "packages",
    "services",
    "ssh",
    "time",
    "updates",
}


class AuditLoader(yaml.SafeLoader):
    pass


AuditLoader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))


def load_yaml(path: Path):
    return yaml.load(path.read_text(), Loader=AuditLoader)


def control_groups(role: Path):
    for path in sorted((role / "vars").glob("*.yml")):
        for name, value in (load_yaml(path) or {}).items():
            if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                controls = [item for item in value if "id" in item and "title" in item]
                if controls:
                    yield path, name, controls


def all_controls(role: Path):
    return [control for _, _, controls in control_groups(role) for control in controls]


def shell_sources(role: Path):
    for control in all_controls(role):
        if control.get("audit"):
            yield f"control {control['id']}", control["audit"]
    for path in sorted((role / "tasks").glob("audit_*.yml")) + [role / "tasks" / "run_control.yml"]:
        if not path.exists():
            continue
        for task in load_yaml(path):
            source = task.get("ansible.builtin.shell")
            if source:
                yield str(path), source


def test_complete_debian_13_catalog_is_unique_and_profiled():
    cis_controls = all_controls(CIS_ROLE)
    health_controls = all_controls(HEALTH_ROLE)
    cis_ids = [control["id"] for control in cis_controls]
    health_ids = [control["id"] for control in health_controls]

    assert len(cis_controls) == 334
    assert len(health_controls) == 62
    assert len(cis_ids) == len(set(cis_ids))
    assert len(health_ids) == len(set(health_ids))
    assert Counter(control["id"].split(".")[0] for control in cis_controls) == {
        "1": 83,
        "2": 45,
        "3": 35,
        "4": 5,
        "5": 72,
        "6": 71,
        "7": 23,
    }
    valid_profiles = {"level1_server", "level2_server", "level1_workstation", "level2_workstation"}
    assert all(set(control["profiles"]) <= valid_profiles for control in cis_controls)
    assert sum("manual" in name for _, name, controls in control_groups(CIS_ROLE) for _ in controls) == 12


def test_portable_catalog_has_no_duplicate_semantics_or_unmapped_categories():
    cis_ids = {str(control["id"]) for control in all_controls(CIS_ROLE)}
    health_controls = all_controls(HEALTH_ROLE)
    semantic_keys = [control["semantic_key"] for control in health_controls]

    assert len(semantic_keys) == len(set(semantic_keys))
    assert {control["category"] for control in health_controls} <= CANONICAL_CATEGORIES
    for control in health_controls:
        superseded_by = control.get("superseded_by", [])
        overlap_ids = {str(value) for value in control.get("overlap_control_ids", [])}
        if "cis_debian13" in superseded_by:
            assert overlap_ids, f"{control['id']} does not identify the benchmark overlap"
            assert overlap_ids <= cis_ids, f"{control['id']} references an unknown benchmark control"


def test_debian_13_active_catalog_suppresses_benchmark_duplicates():
    health_controls = all_controls(HEALTH_ROLE)
    active_health = [
        control for control in health_controls if "cis_debian13" not in control.get("superseded_by", [])
    ]

    assert len(active_health) == 24
    assert len(all_controls(CIS_ROLE)) + len(active_health) == 358


def test_scanner_and_console_share_the_canonical_finding_categories():
    defaults = load_yaml(REPORT_ROLE / "defaults" / "main.yml")
    frontend = Path("apps/web/src/pages/FindingsPage.tsx").read_text()
    frontend_categories = set(re.findall(r"\{ id: '([^']+)', name:", frontend))

    assert set(defaults["lsa_canonical_categories"]) == CANONICAL_CATEGORIES
    assert frontend_categories == CANONICAL_CATEGORIES


def test_supported_operating_system_matrix_is_explicit():
    systems = load_yaml(REPORT_ROLE / "defaults" / "main.yml")["lsa_supported_systems"]

    assert systems["Debian"] == ["12", "13"]
    assert systems["Ubuntu"] == ["22.04", "24.04"]
    for distribution in ("RedHat", "Rocky", "AlmaLinux", "OracleLinux", "CentOS"):
        assert systems[distribution] == ["8", "9"]


def test_every_benchmark_control_has_remediation_guidance():
    remediations = load_yaml(CIS_ROLE / "vars" / "main.yml")["cis_remediations"]
    control_ids = {control["id"] for control in all_controls(CIS_ROLE)}
    assert len(remediations) == 334
    assert set(remediations) == control_ids


def test_audits_contain_no_host_mutation_commands():
    mutating_command = re.compile(
        r"(?:^|[;&]\s*|\|\s+)(?:sudo\s+)?(?:"
        r"apt(?:-get)?\s+(?:install|remove|purge|upgrade|full-upgrade|dist-upgrade|update)|"
        r"(?:dnf|yum)\s+(?:install|remove|erase|upgrade|update|distro-sync)|"
        r"zypper\s+(?:install|remove|update|patch)|apk\s+(?:add|del|upgrade)|"
        r"systemctl\s+(?:enable|disable|start|stop|restart|reload|mask|unmask)|"
        r"service\s+\S+\s+(?:start|stop|restart|reload)|"
        r"sysctl\s+-w|modprobe\s+-r|rmmod|"
        r"chmod|chown|chgrp|passwd|chage|useradd|usermod|userdel|groupadd|groupmod|groupdel|"
        r"mount\s+-o\s+remount|umount\s+\S+|nft\s+(?:add|delete|flush)|ufw\s+(?:enable|disable|allow|deny)|"
        r"firewall-cmd\s+.*(?:--add|--remove|--reload)|iptables\s+-(?:A|D|F|I|N|X)|"
        r"sed\s+-i|rm|mv|cp|install|touch|mkdir|truncate|update-grub|grub-set-password|grubby|aideinit"
        r")\b",
        re.MULTILINE,
    )
    system_write = re.compile(r"(?:^|[^<])(?:>>|>)\s*/(?:etc|boot|usr|var|home|root)(?:/|\b)")
    indirect_system_write = re.compile(
        r"(?:tee\s+(?:-a\s+)?|dd\s+[^\n]*\bof=)/(?:etc|boot|usr|var|home|root)(?:/|\b)"
    )

    violations = []
    for label, source in [*shell_sources(CIS_ROLE), *shell_sources(HEALTH_ROLE)]:
        executable = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        if (
            mutating_command.search(executable)
            or system_write.search(executable)
            or indirect_system_write.search(executable)
        ):
            violations.append(label)
    assert violations == []


def test_remote_audit_tasks_are_explicitly_read_only():
    allowed_modules = {
        "ansible.builtin.assert",
        "ansible.builtin.command",
        "ansible.builtin.debug",
        "ansible.builtin.include_tasks",
        "ansible.builtin.include_vars",
        "ansible.builtin.set_fact",
        "ansible.builtin.shell",
    }
    for role in (CIS_ROLE, HEALTH_ROLE):
        for path in sorted((role / "tasks").glob("*.yml")):
            if path.name == "report.yml":
                continue
            for task in load_yaml(path):
                modules = {key for key in task if key.startswith("ansible.builtin.")}
                assert modules <= allowed_modules, f"{path}: {modules - allowed_modules}"
                if modules & {"ansible.builtin.command", "ansible.builtin.shell"}:
                    assert task.get("changed_when") is False, f"{path}: {task.get('name')}"


def test_all_jinja_expressions_parse():
    environment = Environment()
    for role in (CIS_ROLE, HEALTH_ROLE):
        for path in sorted(role.rglob("*.yml")):
            data = load_yaml(path)

            def visit(value):
                if isinstance(value, dict):
                    for child in value.values():
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)
                elif isinstance(value, str) and "{{" in value:
                    environment.parse(value)

            visit(data)
