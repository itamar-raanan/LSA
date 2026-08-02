import re
from pathlib import Path

import yaml
from jinja2 import Environment


PLUGIN_ROOT = Path("scanner/plugins/debian/cis_13")


def test_debian_13_control_catalog_matches_executable_tasks():
    catalog = yaml.safe_load((PLUGIN_ROOT / "controls.yml").read_text())["controls"]
    task_source = "\n".join(path.read_text() for path in sorted((PLUGIN_ROOT / "tasks").glob("*.yml")))
    catalog_ids = [control["id"] for control in catalog]
    executable_ids = re.findall(r"'control_id': '([^']+)'", task_source)

    assert len(catalog_ids) == 32
    assert len(catalog_ids) == len(set(catalog_ids))
    assert set(catalog_ids) == set(executable_ids)
    assert all(control["severity"] in {"critical", "high", "medium", "low", "info"} for control in catalog)
    supported_profiles = {"production_server", "minimal_server", "router", "container"}
    assert all(set(control.get("profiles", supported_profiles)) <= supported_profiles for control in catalog)


def test_debian_13_plugin_uses_only_read_only_remote_modules():
    task_files = sorted((PLUGIN_ROOT / "tasks").glob("*.yml"))
    allowed_modules = {
        "ansible.builtin.command",
        "ansible.builtin.set_fact",
        "ansible.builtin.stat",
    }
    allowed_modules.add("ansible.builtin.import_tasks")
    for task_file in task_files:
        for task in yaml.safe_load(task_file.read_text()):
            modules = {key for key in task if key.startswith("ansible.builtin.")}
            assert modules <= allowed_modules
            if "ansible.builtin.command" in modules:
                assert task["changed_when"] is False


def test_debian_13_finding_expressions_parse_as_jinja():
    environment = Environment()
    for task_file in sorted((PLUGIN_ROOT / "tasks").glob("*.yml")):
        for task in yaml.safe_load(task_file.read_text()):
            facts = task.get("ansible.builtin.set_fact", {})
            for value in facts.values():
                if isinstance(value, str) and "{{" in value:
                    environment.parse(value)
