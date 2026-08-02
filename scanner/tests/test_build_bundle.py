import json
import zipfile
from pathlib import Path

from scanner.scripts.build_bundle import build


def test_bundle_contains_portable_artifacts(tmp_path: Path):
    fixture = Path("tests/fixtures/report.json")
    bundle_path = build(fixture, tmp_path)
    with zipfile.ZipFile(bundle_path) as bundle:
        names = set(bundle.namelist())
        assert {"manifest.json", "report.json", "report.html", "report.csv", "checksums.sha256"} <= names
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["report_id"] == "0191d6ab-3e3e-7a55-9b70-54a32d536abd"

