import re
from pathlib import Path

import yaml


PLUGIN_ROOT = Path("scanner/plugins/debian/cis_13")


def test_debian_13_control_catalog_matches_executable_tasks():
    catalog = yaml.safe_load((PLUGIN_ROOT / "controls.yml").read_text())["controls"]
    task_source = (PLUGIN_ROOT / "tasks/main.yml").read_text()
    catalog_ids = [control["id"] for control in catalog]
    executable_ids = re.findall(r"'control_id': '([^']+)'", task_source)

    assert len(catalog_ids) == 12
    assert len(catalog_ids) == len(set(catalog_ids))
    assert set(catalog_ids) == set(executable_ids)
    assert all(control["severity"] in {"critical", "high", "medium", "low", "info"} for control in catalog)


def test_debian_13_plugin_uses_only_read_only_remote_modules():
    tasks = yaml.safe_load((PLUGIN_ROOT / "tasks/main.yml").read_text())
    allowed_modules = {
        "ansible.builtin.command",
        "ansible.builtin.set_fact",
        "ansible.builtin.stat",
    }
    for task in tasks:
        modules = {key for key in task if key.startswith("ansible.builtin.")}
        assert modules <= allowed_modules
        if "ansible.builtin.command" in modules:
            assert task["changed_when"] is False
