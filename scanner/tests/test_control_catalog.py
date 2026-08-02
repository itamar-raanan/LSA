import re
from collections import Counter
from pathlib import Path

import yaml
from jinja2 import Environment


CIS_ROLE = Path("scanner/roles/cis_debian13_audit")
HEALTH_ROLE = Path("scanner/roles/linux_security_health")


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
    assert len(health_controls) == 20
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


def test_every_benchmark_control_has_remediation_guidance():
    remediations = load_yaml(CIS_ROLE / "vars" / "main.yml")["cis_remediations"]
    control_ids = {control["id"] for control in all_controls(CIS_ROLE)}
    assert len(remediations) == 334
    assert set(remediations) == control_ids


def test_audits_contain_no_host_mutation_commands():
    mutating_command = re.compile(
        r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:"
        r"apt(?:-get)?\s+(?:install|remove|purge|upgrade|full-upgrade|dist-upgrade|update)|"
        r"systemctl\s+(?:enable|disable|start|stop|restart|reload|mask|unmask)|"
        r"service\s+\S+\s+(?:start|stop|restart|reload)|"
        r"sysctl\s+-w|modprobe\s+-r|rmmod|"
        r"chmod|chown|chgrp|useradd|usermod|userdel|groupadd|groupmod|groupdel|"
        r"mount\s+-o\s+remount|umount\s+\S+|nft\s+(?:add|delete|flush)|ufw\s+(?:enable|disable|allow|deny)|"
        r"rm|mv|cp|install|touch|mkdir|truncate|update-grub|grub-set-password|aideinit"
        r")\b",
        re.MULTILINE,
    )
    system_write = re.compile(r"(?:^|[^<])(?:>>|>)\s*/(?:etc|boot|usr|var|home|root)(?:/|\b)")

    violations = []
    for label, source in [*shell_sources(CIS_ROLE), *shell_sources(HEALTH_ROLE)]:
        executable = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        if mutating_command.search(executable) or system_write.search(executable):
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
