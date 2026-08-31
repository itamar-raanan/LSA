import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.integrity import build_manifest, verify_manifest, write_manifest
from agent.lsa_agent import (
    AGENT_CAPABILITIES,
    apply_platform_key_rotation,
    VERSION,
    _scan_due,
    accept_policy_version,
    http_client,
    platform_url,
    process_recovery_verification,
    process_remediation_checkpoint,
    process_remediation_validation,
    run_scanner,
    signed_control_get,
    signed_headers,
    verify_control_response,
    verify_platform_envelope,
)
from agent.remediation_contract import (
    RemediationContractError,
    canonical_validation_receipt,
    dry_run_remediation_contract,
    sign_validation_receipt,
    validate_remediation_contract_preview,
)
from agent.remediation_recovery import (
    compile_recovery_plan,
    create_encrypted_checkpoints,
    verify_encrypted_checkpoints,
)
from lsa.services.remediation_catalog import load_remediation_catalog


def test_runtime_version_matches_packaging_release():
    assert Path("agent/VERSION").read_text(encoding="utf-8").strip() == VERSION


def test_enrollment_uses_only_the_integrity_protected_offline_wheelhouse():
    script = Path("agent/lsa-agent-enroll").read_text(encoding="utf-8")
    assert 'WHEELHOUSE_DIR="$INSTALL_DIR/wheelhouse"' in script
    assert '--no-index' in script
    assert '--find-links "$WHEELHOUSE_DIR"' in script
    assert '"$INSTALL_DIR/venv/bin/pip" check' in script
    assert "pip install --disable-pip-version-check --no-cache-dir -r" not in script


def test_agent_attests_governance_planning_without_write_execution():
    assert "signed-change-set-planning-v1" in AGENT_CAPABILITIES
    assert "signed-platform-control-v1" in AGENT_CAPABILITIES
    assert "platform-key-rotation-v1" in AGENT_CAPABILITIES
    assert "remediation-contract-validation-v1" in AGENT_CAPABILITIES
    assert "remediation-dry-run-v1" in AGENT_CAPABILITIES
    assert "remediation-recovery-planning-v1" in AGENT_CAPABILITIES
    assert "remediation-checkpoint-v1" in AGENT_CAPABILITIES
    assert "remediation-recovery-verification-v1" in AGENT_CAPABILITIES
    assert all("execute" not in capability and "write" not in capability for capability in AGENT_CAPABILITIES)


def remediation_contract_fixture() -> tuple[dict, Ed25519PrivateKey, bytes]:
    platform_key = Ed25519PrivateKey.generate()
    platform_raw = platform_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    change_key = Ed25519PrivateKey.generate()
    change_raw = change_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    change_descriptor = {
        "key_id": "change-key-1",
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(change_raw).decode(),
        "fingerprint": hashlib.sha256(change_raw).hexdigest(),
    }
    action = next(
        item for item in load_remediation_catalog() if "CIS-DEBIAN13-5.1.21" in item.control_ids
    ).model_dump(mode="json")
    target = {
        "host_id": "host-1",
        "hostname": "host-1.example.test",
        "agent_id": "agent-1",
        "group_id": "group-1",
        "group_name": "Canary Linux",
        "policy_id": "policy-1",
        "policy_name": "Remediation (Approval Required)",
        "policy_version": 4,
        "rollout_phase": "canary",
        "required_capability": "signed-change-set-planning-v1",
        "capability_attested": True,
    }
    plan = {
        "plan_id": "plan-1",
        "host_id": "host-1",
        "report_id": "report-1",
        "control_id": "CIS-DEBIAN13-5.1.21",
        "action_id": action["action_id"],
        "action_version": action["version"],
        "action_digest": action["digest"],
    }
    start = datetime.now(UTC) + timedelta(minutes=10)
    payload = {
        "schema_version": "1.0",
        "change_set_id": "change-set-1",
        "tenant_id": "tenant-1",
        "requested_at": datetime.now(UTC).isoformat(),
        "maintenance_window": {
            "start": start.isoformat(),
            "end": (start + timedelta(hours=2)).isoformat(),
        },
        "rollout": {"strategy": "canary", "batch_size": 1, "batch_interval_minutes": 15},
        "safeguards": {
            "execution_enabled": False,
            "four_eyes_required": True,
            "post_change_verification_required": True,
            "rollback_checkpoint_required": True,
        },
        "plans": [plan],
        "targets": [target],
    }
    canonical_payload = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    endorsement = {
        "schema_version": "1.0",
        "kind": "change-signing-key-endorsement",
        "tenant_id": "tenant-1",
        "purpose": "remediation-validation",
        "platform_command_key_id": "platform-key-1",
        "change_signing_key": change_descriptor,
    }
    canonical_endorsement = json.dumps(
        endorsement, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    contract = {
        "schema_version": "1.0",
        "contract_type": "remediation-validation",
        "mode": "validate_only",
        "execution_enabled": False,
        "dispatch_enabled": False,
        "change_set": {
            "change_set_id": "change-set-1",
            "tenant_id": "tenant-1",
            "digest": hashlib.sha256(canonical_payload).hexdigest(),
            "payload": payload,
            "signature": base64.b64encode(change_key.sign(canonical_payload)).decode(),
            "signing_key": change_descriptor,
        },
        "platform_endorsement": endorsement,
        "platform_endorsement_signature": base64.b64encode(
            platform_key.sign(canonical_endorsement)
        ).decode(),
        "target": dict(target),
        "actions": [
            {
                "plan_id": "plan-1",
                "host_id": "host-1",
                "control_id": "CIS-DEBIAN13-5.1.21",
                "action_id": action["action_id"],
                "action_version": action["version"],
                "action_digest": action["digest"],
                "action_snapshot": action,
            }
        ],
    }
    return contract, platform_key, platform_raw


def validate_contract_fixture(contract, platform_key, platform_raw):
    return validate_remediation_contract_preview(
        contract,
        pinned_platform_key=platform_key.public_key(),
        pinned_platform_raw=platform_raw,
        expected_platform_key_id="platform-key-1",
        expected_agent_id="agent-1",
        expected_host_id="host-1",
    )


def test_agent_validates_contract_without_exposing_an_execution_payload():
    contract, platform_key, platform_raw = remediation_contract_fixture()
    result = validate_contract_fixture(contract, platform_key, platform_raw)
    assert result["validated"] is True
    assert result["mode"] == "validate_only"
    assert result["execution_enabled"] is False
    assert result["dispatch_enabled"] is False
    assert result["action_count"] == 1
    assert "actions" not in result


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"execution_enabled": True}), "safety lock"),
        (
            lambda value: value["target"].update({"agent_id": "agent-other"}),
            "target binding",
        ),
        (
            lambda value: value["actions"][0]["action_snapshot"].update(
                {"command": "touch /tmp/unsafe"}
            ),
            "schema is invalid",
        ),
        (
            lambda value: value["actions"][0].update({"action_digest": "0" * 64}),
            "does not match",
        ),
        (
            lambda value: value["actions"][0]["action_snapshot"].update({"rollback": []}),
            "digest is invalid",
        ),
    ],
)
def test_agent_rejects_mutated_or_executable_contracts(mutation, message):
    contract, platform_key, platform_raw = remediation_contract_fixture()
    mutation(contract)
    with pytest.raises(RemediationContractError, match=message):
        validate_contract_fixture(contract, platform_key, platform_raw)


def test_agent_rejects_unendorsed_change_signing_key():
    contract, platform_key, platform_raw = remediation_contract_fixture()
    replacement = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    contract["platform_endorsement"]["change_signing_key"] = {
        "key_id": "attacker-key",
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(replacement).decode(),
        "fingerprint": hashlib.sha256(replacement).hexdigest(),
    }
    with pytest.raises(RemediationContractError, match="platform endorsement signature"):
        validate_contract_fixture(contract, platform_key, platform_raw)


def test_agent_rejects_mismatched_pinned_platform_key_material():
    contract, platform_key, _ = remediation_contract_fixture()
    other_raw = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    with pytest.raises(RemediationContractError, match="platform endorsement binding"):
        validate_contract_fixture(contract, platform_key, other_raw)


def test_agent_dry_run_reports_manual_gate_without_writing(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    (tmp_path / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID="debian"\nVERSION_ID="13"\n')
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    result = dry_run_remediation_contract(
        contract,
        root=tmp_path,
        command_lookup=lambda _: "/usr/bin/reviewed-program",
    )
    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert result["status"] == "blocked"
    assert result["execution_enabled"] is False
    assert result["changes_applied"] is False
    assert any(
        item["status"] == "blocked" and "Manual confirmation" in item["detail"]
        for item in result["action_results"][0]["checks"]
    )
    assert after == before


def test_agent_dry_run_can_mark_fully_satisfied_preflight_ready(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    action = contract["actions"][0]["action_snapshot"]
    action["preconditions"] = [
        item for item in action["preconditions"] if item["kind"] != "manual_confirmation"
    ]
    (tmp_path / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(
        "Package: openssh-server\nStatus: install ok installed\n"
    )
    (tmp_path / "etc/os-release").write_text('ID="debian"\nVERSION_ID="13"\n')
    result = dry_run_remediation_contract(
        contract,
        root=tmp_path,
        command_lookup=lambda _: "/usr/bin/reviewed-program",
    )
    assert result["status"] == "ready"
    assert result["action_results"][0]["status"] == "ready"
    assert all(
        item["status"] == "passed" for item in result["action_results"][0]["checks"]
    )


def test_agent_compiles_read_only_recovery_plan_with_original_file_evidence(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    target = tmp_path / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    target.chmod(0o640)
    before = target.read_bytes()

    plan = compile_recovery_plan(contract, root=tmp_path)

    assert plan["status"] == "ready"
    assert plan["execution_enabled"] is False
    assert plan["changes_applied"] is False
    assert plan["journal_state"] == "planned"
    assert len(plan["entries"]) == 1
    entry = plan["entries"][0]
    assert entry["source_state"] == "regular_file"
    assert entry["source_digest"] == f"sha256:{hashlib.sha256(before).hexdigest()}"
    assert entry["mode"] == "0640"
    assert entry["backup_created"] is False
    assert plan["rollback_order"] == [entry["checkpoint_id"]]
    assert target.read_bytes() == before


def test_agent_recovery_plan_blocks_symbolic_links_and_overlapping_actions(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    target = tmp_path / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("unsafe\n", encoding="utf-8")
    target.symlink_to(outside)

    symbolic = compile_recovery_plan(contract, root=tmp_path)
    assert symbolic["status"] == "blocked"
    assert "symbolic link" in symbolic["entries"][0]["detail"]

    target.unlink()
    duplicate = dict(contract["actions"][0])
    duplicate["plan_id"] = "plan-2"
    contract["actions"].append(duplicate)
    overlapping = compile_recovery_plan(contract, root=tmp_path)
    assert overlapping["status"] == "blocked"
    assert all("multiple actions" in entry["detail"] for entry in overlapping["entries"])


def test_agent_creates_only_encrypted_local_checkpoints_and_a_durable_journal(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    root = tmp_path / "root"
    state_dir = tmp_path / "state"
    target = root / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    plaintext = b"PermitRootLogin yes\nSensitiveSetting hidden\n"
    target.write_bytes(plaintext)
    target.chmod(0o640)
    plan = compile_recovery_plan(contract, root=root)

    journal = create_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-1",
        validation_id="validation-1",
        contract_digest="c" * 64,
        recovery_plan=plan,
        state_dir=state_dir,
        root=root,
    )

    assert journal["state"] == "checkpointed"
    assert journal["execution_enabled"] is False
    assert journal["changes_applied"] is False
    result = journal["checkpoint_results"][0]
    assert result["backup_created"] is True
    blob = (
        state_dir
        / "remediation-checkpoints/checkpoint-job-1"
        / f"{result['checkpoint_id']}.bin"
    )
    assert blob.is_file()
    assert plaintext not in blob.read_bytes()
    assert blob.stat().st_mode & 0o077 == 0
    assert (state_dir / "remediation-checkpoints").stat().st_mode & 0o077 == 0
    assert blob.parent.stat().st_mode & 0o077 == 0
    assert (state_dir / "remediation-checkpoints.key").stat().st_mode & 0o077 == 0
    assert target.read_bytes() == plaintext
    assert create_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-1",
        validation_id="validation-1",
        contract_digest="c" * 64,
        recovery_plan=plan,
        state_dir=state_dir,
        root=root,
    ) == journal


def test_agent_checkpoint_blocks_when_source_changed_after_preflight(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    root = tmp_path / "root"
    target = root / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    plan = compile_recovery_plan(contract, root=root)
    target.write_text("PermitRootLogin no\n", encoding="utf-8")

    journal = create_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-2",
        validation_id="validation-2",
        contract_digest="d" * 64,
        recovery_plan=plan,
        state_dir=tmp_path / "state",
        root=root,
    )

    assert journal["state"] == "blocked"
    assert "changed after recovery planning" in journal["error"]
    assert journal["checkpoint_results"] == [
        {
            "checkpoint_id": plan["entries"][0]["checkpoint_id"],
            "source_state": "regular_file",
            "status": "blocked",
            "backup_created": False,
            "encrypted_blob_digest": None,
            "encrypted_size_bytes": None,
            "error": "checkpoint source changed after recovery planning",
        }
    ]
    assert target.read_text(encoding="utf-8") == "PermitRootLogin no\n"


def test_agent_checkpoint_blocks_when_an_absent_source_appears_after_preflight(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    root = tmp_path / "root"
    target = root / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    plan = compile_recovery_plan(contract, root=root)
    assert plan["entries"][0]["source_state"] == "absent"
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")

    journal = create_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-3",
        validation_id="validation-3",
        contract_digest="e" * 64,
        recovery_plan=plan,
        state_dir=tmp_path / "state",
        root=root,
    )

    assert journal["state"] == "blocked"
    assert journal["checkpoint_results"][0]["status"] == "blocked"
    assert "changed after recovery planning" in journal["error"]
    assert target.read_text(encoding="utf-8") == "PermitRootLogin yes\n"


def test_agent_reverifies_encrypted_checkpoints_and_detects_tampering(tmp_path):
    contract, _, _ = remediation_contract_fixture()
    root = tmp_path / "root"
    state_dir = tmp_path / "state"
    target = root / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    plan = compile_recovery_plan(contract, root=root)
    journal = create_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-verify",
        validation_id="validation-verify",
        contract_digest="f" * 64,
        recovery_plan=plan,
        state_dir=state_dir,
        root=root,
    )
    journal_digest = hashlib.sha256(
        json.dumps(journal, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()

    verified = verify_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-verify",
        validation_id="validation-verify",
        contract_digest="f" * 64,
        recovery_plan=plan,
        expected_journal_digest=journal_digest,
        state_dir=state_dir,
    )
    assert verified["state"] == "verified"
    assert verified["verification_results"][0]["status"] == "verified"
    assert verified["execution_enabled"] is False
    assert target.read_text(encoding="utf-8") == "PermitRootLogin yes\n"

    blob = next((state_dir / "remediation-checkpoints/checkpoint-job-verify").glob("*.bin"))
    corrupted = bytearray(blob.read_bytes())
    corrupted[-1] ^= 1
    blob.write_bytes(corrupted)
    blob.chmod(0o600)
    blocked = verify_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-verify",
        validation_id="validation-verify",
        contract_digest="f" * 64,
        recovery_plan=plan,
        expected_journal_digest=journal_digest,
        state_dir=state_dir,
    )
    assert blocked["state"] == "blocked"
    assert blocked["verification_results"][0]["status"] == "blocked"
    assert target.read_text(encoding="utf-8") == "PermitRootLogin yes\n"


def test_agent_validation_receipt_has_an_independent_signature():
    key = Ed25519PrivateKey.generate()
    receipt = {
        "schema_version": "1.0",
        "kind": "remediation-validation-receipt",
        "validation_id": "validation-1",
        "change_set_id": "change-set-1",
        "contract_digest": "a" * 64,
        "agent_id": "agent-1",
        "host_id": "host-1",
        "status": "blocked",
        "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
        "changes_applied": False,
        "agent_version": "0.9.0",
        "agent_integrity_digest": f"sha256:{'b' * 64}",
        "action_results": [],
        "error": "Preflight blocked",
    }
    signature = sign_validation_receipt(key, receipt)
    key.public_key().verify(base64.b64decode(signature), canonical_validation_receipt(receipt))


def test_agent_processes_and_caches_the_exact_signed_dry_run_receipt(tmp_path, monkeypatch):
    contract, _, platform_raw = remediation_contract_fixture()
    platform_key_path = tmp_path / "platform-command-key.pub"
    platform_key_path.write_text(base64.b64encode(platform_raw).decode() + "\n")
    config = {
        "state_dir": str(tmp_path / "state"),
        "platform_command_key_file": str(platform_key_path),
    }
    state = {
        "agent_id": "agent-1",
        "host_id": "host-1",
        "platform_command_key_id": "platform-key-1",
        "integrity_manifest_sha256": f"sha256:{'c' * 64}",
    }
    contract_digest = hashlib.sha256(
        json.dumps(
            contract,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    payload = {
        "validation": {
            "validation_id": "validation-1",
            "change_set_id": "change-set-1",
            "contract_digest": contract_digest,
            "contract": contract,
        }
    }
    agent_key = Ed25519PrivateKey.generate()
    submitted = []

    def accept_receipt(_config, _state, _key, _path, body, _kind):
        submitted.append(body)
        return {"accepted": True}

    monkeypatch.setattr("agent.lsa_agent.signed_control_post", accept_receipt)
    first = process_remediation_validation(config, state, agent_key, payload)
    second = process_remediation_validation(config, state, agent_key, payload)
    assert first == second
    assert first["changes_applied"] is False
    assert submitted[0] == submitted[1]
    receipt = submitted[0]["receipt"]
    assert receipt["execution_enabled"] is False
    assert receipt["changes_applied"] is False
    assert receipt["recovery_plan"]["execution_enabled"] is False
    assert receipt["recovery_plan"]["backup_before_write"] is True
    agent_key.public_key().verify(
        base64.b64decode(submitted[0]["signature"]),
        canonical_validation_receipt(receipt),
    )
    assert (tmp_path / "state/state.json").is_file()


def test_agent_processes_and_retries_the_exact_encrypted_checkpoint_receipt(
    tmp_path, monkeypatch
):
    contract, _, platform_raw = remediation_contract_fixture()
    root = tmp_path / "root"
    target = root / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    recovery_plan = compile_recovery_plan(contract, root=root)
    platform_key_path = tmp_path / "platform-command-key.pub"
    platform_key_path.write_text(base64.b64encode(platform_raw).decode() + "\n")
    config = {
        "state_dir": str(tmp_path / "state"),
        "inspection_root": str(root),
        "platform_command_key_file": str(platform_key_path),
    }
    state = {
        "agent_id": "agent-1",
        "host_id": "host-1",
        "platform_command_key_id": "platform-key-1",
        "integrity_manifest_sha256": f"sha256:{'c' * 64}",
    }
    contract_digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    payload = {
        "checkpoint": {
            "checkpoint_job_id": "checkpoint-job-1",
            "validation_id": "validation-1",
            "change_set_id": "change-set-1",
            "contract_digest": contract_digest,
            "contract": contract,
            "recovery_plan": recovery_plan,
        }
    }
    agent_key = Ed25519PrivateKey.generate()
    submitted = []

    def accept_receipt(_config, _state, _key, _path, body, _kind):
        submitted.append(body)
        return {"accepted": True}

    monkeypatch.setattr("agent.lsa_agent.signed_control_post", accept_receipt)
    first = process_remediation_checkpoint(config, state, agent_key, payload)
    second = process_remediation_checkpoint(config, state, agent_key, payload)

    assert first == second == {
        "checkpoint_job_id": "checkpoint-job-1",
        "status": "ready",
        "changes_applied": False,
    }
    assert submitted[0] == submitted[1]
    receipt = submitted[0]["receipt"]
    assert receipt["journal_state"] == "checkpointed"
    assert receipt["checkpoint_results"][0]["backup_created"] is True
    agent_key.public_key().verify(
        base64.b64decode(submitted[0]["signature"]),
        canonical_validation_receipt(receipt),
    )


def test_agent_processes_and_caches_signed_recovery_verification(tmp_path, monkeypatch):
    contract, _, platform_raw = remediation_contract_fixture()
    root = tmp_path / "root"
    state_dir = tmp_path / "state"
    target = root / "etc/ssh/sshd_config.d/90-lsa-hardening.conf"
    target.parent.mkdir(parents=True)
    target.write_text("PermitRootLogin yes\n", encoding="utf-8")
    recovery_plan = compile_recovery_plan(contract, root=root)
    contract_digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    journal = create_encrypted_checkpoints(
        checkpoint_job_id="checkpoint-job-verify",
        validation_id="validation-verify",
        contract_digest=contract_digest,
        recovery_plan=recovery_plan,
        state_dir=state_dir,
        root=root,
    )
    journal_digest = hashlib.sha256(
        json.dumps(journal, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    platform_key_path = tmp_path / "platform-command-key.pub"
    platform_key_path.write_text(base64.b64encode(platform_raw).decode() + "\n")
    config = {
        "state_dir": str(state_dir),
        "platform_command_key_file": str(platform_key_path),
    }
    state = {
        "agent_id": "agent-1",
        "host_id": "host-1",
        "platform_command_key_id": "platform-key-1",
        "integrity_manifest_sha256": f"sha256:{'c' * 64}",
    }
    payload = {
        "verification": {
            "verification_job_id": "verification-job-1",
            "checkpoint_job_id": "checkpoint-job-verify",
            "validation_id": "validation-verify",
            "change_set_id": "change-set-1",
            "contract_digest": contract_digest,
            "contract": contract,
            "recovery_plan": recovery_plan,
            "checkpoint_journal_digest": journal_digest,
        }
    }
    agent_key = Ed25519PrivateKey.generate()
    submitted = []

    def accept_receipt(_config, _state, _key, _path, body, _kind):
        submitted.append(body)
        return {"accepted": True}

    monkeypatch.setattr("agent.lsa_agent.signed_control_post", accept_receipt)
    first = process_recovery_verification(config, state, agent_key, payload)
    second = process_recovery_verification(config, state, agent_key, payload)

    assert first == second == {
        "verification_job_id": "verification-job-1",
        "status": "ready",
        "changes_applied": False,
    }
    assert submitted[0] == submitted[1]
    receipt = submitted[0]["receipt"]
    assert receipt["verification_state"] == "verified"
    assert receipt["verification_results"][0]["status"] == "verified"
    assert receipt["changes_applied"] is False
    agent_key.public_key().verify(
        base64.b64decode(submitted[0]["signature"]),
        canonical_validation_receipt(receipt),
    )


def test_platform_requires_https_by_default():
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        platform_url({"platform_url": "http://lsa.example.test:8444"})


def test_agent_http_client_disables_server_certificate_verification(monkeypatch):
    captured = {}

    class Client:
        pass

    def client_factory(**kwargs):
        captured.update(kwargs)
        return Client()

    monkeypatch.setattr("agent.lsa_agent.httpx.Client", client_factory)

    assert isinstance(
        http_client(
            {
                "platform_url": "https://lsa.example.test:8444",
                "ca_bundle": "/path/from/an/older/config.crt",
            }
        ),
        Client,
    )
    assert captured["verify"] is False


def test_agent_request_signature_covers_method_path_timestamp_and_body():
    key = Ed25519PrivateKey.generate()
    body = b'{"agent_version":"0.1.0"}'
    headers = signed_headers(key, "agent-id", "POST", "/api/v1/agent/heartbeat", body)
    message = (
        "POST\n/api/v1/agent/heartbeat\n"
        f"{headers['X-LSA-Agent-Timestamp']}\n{hashlib.sha256(body).hexdigest()}"
    ).encode()
    key.public_key().verify(base64.b64decode(headers["X-LSA-Agent-Signature"]), message)
    assert headers["X-LSA-Platform-Control"] == "signed-v1"


def test_scan_schedule_treats_missing_and_expired_deadlines_as_due():
    assert _scan_due({}) is True
    assert _scan_due({"next_scan_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}) is True
    assert _scan_due({"next_scan_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()}) is False


def test_policy_version_cannot_roll_back():
    state = {"policy_version": 3, "highest_policy_version": 3}
    assert accept_policy_version(state, {"policy_version": 4}) == 4
    assert state["highest_policy_version"] == 4
    with pytest.raises(RuntimeError, match="policy rollback rejected"):
        accept_policy_version(state, {"policy_version": 3})


def signed_platform_envelope(
    *,
    key: Ed25519PrivateKey | None = None,
    sequence: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    identity_fingerprint: str = "agent-fingerprint",
    execution_enabled: bool = False,
):
    key = key or Ed25519PrivateKey.generate()
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    current = datetime.now(UTC)
    envelope = {
        "schema_version": "1.0",
        "kind": "agent-enrollment",
        "key_id": "platform-key-1",
        "sequence": sequence,
        "issued_at": (issued_at or current).isoformat(),
        "expires_at": (expires_at or current + timedelta(minutes=5)).isoformat(),
        "agent_id": "agent-1",
        "payload": {
            "agent_id": "agent-1",
            "host_id": "host-1",
            "agent_identity_fingerprint": identity_fingerprint,
            "execution_enabled": execution_enabled,
        },
    }
    canonical = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    trust = {
        "key_id": "platform-key-1",
        "key_version": 1,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public_raw).decode(),
        "fingerprint": hashlib.sha256(public_raw).hexdigest(),
    }
    return envelope, base64.b64encode(key.sign(canonical)).decode(), trust, key.public_key(), public_raw


def test_platform_envelope_accepts_pinned_identity_and_records_sequence():
    envelope, signature, trust, key, raw = signed_platform_envelope()
    payload = verify_platform_envelope(
        envelope,
        signature,
        trust,
        key,
        raw,
        expected_kind="agent-enrollment",
        expected_identity_fingerprint="agent-fingerprint",
    )
    assert payload["platform_envelope_sequence"] == 1
    assert payload["platform_command_key_fingerprint"] == trust["fingerprint"]


def test_platform_envelope_rejects_a_different_pinned_platform_key():
    envelope, signature, trust, _, _ = signed_platform_envelope()
    other = Ed25519PrivateKey.generate()
    other_raw = other.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    with pytest.raises(RuntimeError, match="does not match the pinned key"):
        verify_platform_envelope(
            envelope,
            signature,
            trust,
            other.public_key(),
            other_raw,
            expected_kind="agent-enrollment",
            expected_identity_fingerprint="agent-fingerprint",
        )


def test_control_response_uses_persisted_agent_binding_and_sequence(tmp_path):
    envelope, signature, trust, _, _ = signed_platform_envelope(sequence=2)
    envelope["kind"] = "agent-policy"
    key = Ed25519PrivateKey.generate()
    # Re-sign with a key whose raw bytes are installed as the platform pin.
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust.update(
        public_key=base64.b64encode(public_raw).decode(),
        fingerprint=hashlib.sha256(public_raw).hexdigest(),
    )
    signature = base64.b64encode(
        key.sign(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode())
    ).decode()
    pin = tmp_path / "platform.pub"
    pin.write_text(trust["public_key"], encoding="utf-8")
    state = {
        "agent_id": "agent-1",
        "agent_identity_fingerprint": "agent-fingerprint",
        "platform_envelope_sequence": 1,
    }
    payload = verify_control_response(
        {"platform_envelope": envelope, "platform_signature": signature, "platform_trust": trust},
        {"platform_command_key_file": str(pin)},
        state,
        expected_kind="agent-policy",
    )
    assert payload["platform_envelope_sequence"] == 2


def test_control_response_rejects_unsigned_data(tmp_path):
    pin = tmp_path / "platform.pub"
    pin.write_text(base64.b64encode(b"x" * 32).decode(), encoding="utf-8")
    with pytest.raises(RuntimeError, match="did not return a signed agent-policy response"):
        verify_control_response(
            {"policy_version": 2},
            {"platform_command_key_file": str(pin)},
            {
                "agent_id": "agent-1",
                "agent_identity_fingerprint": "agent-fingerprint",
                "platform_envelope_sequence": 1,
            },
            expected_kind="agent-policy",
        )


def test_control_response_persists_sequence_before_returning(tmp_path, monkeypatch):
    envelope, _, trust, _, _ = signed_platform_envelope(sequence=2)
    envelope["kind"] = "agent-policy"
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust.update(
        public_key=base64.b64encode(raw).decode(),
        fingerprint=hashlib.sha256(raw).hexdigest(),
    )
    signature = base64.b64encode(
        key.sign(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode())
    ).decode()
    pin = tmp_path / "platform.pub"
    pin.write_text(base64.b64encode(raw).decode(), encoding="utf-8")
    config = {
        "state_dir": str(tmp_path / "state"),
        "platform_command_key_file": str(pin),
    }
    state = {
        "agent_id": "agent-1",
        "agent_identity_fingerprint": "agent-fingerprint",
        "platform_envelope_sequence": 1,
    }
    monkeypatch.setattr(
        "agent.lsa_agent.signed_get",
        lambda *_: {
            "platform_envelope": envelope,
            "platform_signature": signature,
            "platform_trust": trust,
        },
    )
    payload = signed_control_get(config, state, object(), "/policy", "agent-policy")
    assert payload["agent_id"] == "agent-1"
    persisted = json.loads((tmp_path / "state" / "state.json").read_text())
    assert persisted["platform_envelope_sequence"] == 2


def test_platform_key_rotation_requires_both_signatures_and_promotes_atomically(tmp_path):
    current = Ed25519PrivateKey.generate()
    current_raw = current.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    next_key = Ed25519PrivateKey.generate()
    next_raw = next_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    next_trust = {
        "key_id": "platform-key-2",
        "key_version": 2,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(next_raw).decode(),
        "fingerprint": hashlib.sha256(next_raw).hexdigest(),
    }
    proposal = {
        "schema_version": "1.0",
        "kind": "platform-key-rotation",
        "previous_key_id": "platform-key-1",
        "next_key": next_trust,
        "created_at": datetime.now(UTC).isoformat(),
    }
    canonical = json.dumps(
        proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    state = {
        "platform_command_key_id": "platform-key-1",
        "platform_command_key_version": 1,
        "platform_command_key_fingerprint": hashlib.sha256(current_raw).hexdigest(),
    }
    pin = tmp_path / "platform.pub"
    pin.write_text(base64.b64encode(current_raw).decode(), encoding="utf-8")
    config = {"platform_command_key_file": str(pin)}
    apply_platform_key_rotation(
        {
            "platform_key_rotation": {
                "phase": "staged",
                "proposal": proposal,
                "previous_key_signature": base64.b64encode(current.sign(canonical)).decode(),
                "next_key_signature": base64.b64encode(next_key.sign(canonical)).decode(),
            }
        },
        config,
        state,
        current_raw,
    )
    assert state["pending_platform_trust"] == next_trust
    assert pin.read_text() == base64.b64encode(current_raw).decode()

    apply_platform_key_rotation(
        {
            "platform_key_rotation": {"phase": "activated", "next_key": next_trust},
            "platform_command_key_id": next_trust["key_id"],
            "platform_command_key_version": next_trust["key_version"],
        },
        config,
        state,
        next_raw,
    )
    assert state["platform_command_key_fingerprint"] == next_trust["fingerprint"]
    assert "pending_platform_trust" not in state
    assert pin.read_text().strip() == next_trust["public_key"]


def test_platform_key_rotation_rejects_missing_next_key_proof(tmp_path):
    current = Ed25519PrivateKey.generate()
    current_raw = current.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    next_key = Ed25519PrivateKey.generate()
    next_raw = next_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    next_trust = {
        "key_id": "platform-key-2",
        "key_version": 2,
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(next_raw).decode(),
        "fingerprint": hashlib.sha256(next_raw).hexdigest(),
    }
    proposal = {
        "schema_version": "1.0",
        "kind": "platform-key-rotation",
        "previous_key_id": "platform-key-1",
        "next_key": next_trust,
        "created_at": datetime.now(UTC).isoformat(),
    }
    canonical = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(RuntimeError, match="rotation proof is invalid"):
        apply_platform_key_rotation(
            {
                "platform_key_rotation": {
                    "phase": "staged",
                    "proposal": proposal,
                    "previous_key_signature": base64.b64encode(current.sign(canonical)).decode(),
                    "next_key_signature": base64.b64encode(b"x" * 64).decode(),
                }
            },
            {},
            {
                "platform_command_key_id": "platform-key-1",
                "platform_command_key_fingerprint": hashlib.sha256(current_raw).hexdigest(),
            },
            current_raw,
        )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("tamper", "signature is invalid"),
        ("expired", "expired"),
        ("future", "future"),
        ("replay", "replay or rollback"),
        ("identity", "another agent identity"),
        ("execution", "audit-only safety lock"),
    ],
)
def test_platform_envelope_rejects_untrusted_or_replayed_control_data(change, message):
    now = datetime.now(UTC)
    kwargs = {}
    state = None
    expected_identity = "agent-fingerprint"
    if change == "expired":
        kwargs = {"issued_at": now - timedelta(minutes=6), "expires_at": now - timedelta(minutes=1)}
    elif change == "future":
        kwargs = {"issued_at": now + timedelta(minutes=6), "expires_at": now + timedelta(minutes=9)}
    elif change == "replay":
        state = {"agent_id": "agent-1", "platform_envelope_sequence": 1}
    elif change == "identity":
        expected_identity = "different-agent"
    elif change == "execution":
        kwargs = {"execution_enabled": True}
    envelope, signature, trust, key, raw = signed_platform_envelope(**kwargs)
    if change == "tamper":
        envelope["payload"]["host_id"] = "attacker-host"
    with pytest.raises(RuntimeError, match=message):
        verify_platform_envelope(
            envelope,
            signature,
            trust,
            key,
            raw,
            expected_kind="agent-enrollment",
            expected_identity_fingerprint=expected_identity,
            state=state,
            now=now,
        )


def test_scanner_uses_writable_ansible_runtime_paths_under_agent_state(tmp_path, monkeypatch):
    scanner_dir = tmp_path / "scanner"
    (scanner_dir / "playbooks").mkdir(parents=True)
    (scanner_dir / "playbooks" / "scan.yml").write_text("---\n", encoding="utf-8")
    (scanner_dir / "ansible.cfg").write_text("[defaults]\n", encoding="utf-8")
    state_dir = tmp_path / "state"
    key_path = tmp_path / "agent-signing-key.pem"

    def fake_run(command, *, cwd, env, check):
        assert cwd == scanner_dir
        assert check is True
        assert command[0] == "/opt/lsa-agent/venv/bin/ansible-playbook"
        assert env["ANSIBLE_CONFIG"] == str(scanner_dir / "ansible.cfg")

        runtime_paths = (
            env["ANSIBLE_HOME"],
            env["ANSIBLE_LOCAL_TEMP"],
            env["ANSIBLE_REMOTE_TEMP"],
            env["ANSIBLE_REMOTE_TMP"],
        )
        assert env["ANSIBLE_REMOTE_TEMP"] == env["ANSIBLE_REMOTE_TMP"]
        for value in runtime_paths:
            path = Path(value)
            assert path.is_relative_to(state_dir)
            assert path.is_dir()
            assert path.stat().st_mode & 0o777 == 0o700

    monkeypatch.setattr("agent.lsa_agent.subprocess.run", fake_run)
    run_scanner(
        {
            "scanner_dir": str(scanner_dir),
            "state_dir": str(state_dir),
            "platform_url": "https://lsa.example.test:8444",
            "ansible_playbook": "/opt/lsa-agent/venv/bin/ansible-playbook",
        },
        {
            "host_id": "host-id",
            "ingestion_token": "ingestion-token",
            "signing_key_id": "signing-key-id",
        },
        key_path,
        {"enforcement_enabled": False, "settings": {}, "default_mode": "audit"},
    )


def test_runtime_manifest_detects_modified_managed_file(tmp_path):
    (tmp_path / "agent").mkdir()
    (tmp_path / "scanner").mkdir()
    runtime = tmp_path / "agent" / "runtime.py"
    runtime.write_text("safe = True\n", encoding="utf-8")
    (tmp_path / "scanner" / "control.yml").write_text("id: example\n", encoding="utf-8")
    manifest = tmp_path / "integrity-manifest.json"
    write_manifest(tmp_path, manifest)

    assert build_manifest(tmp_path)["files"]
    assert len(verify_manifest(tmp_path, manifest)) == 64
    runtime.write_text("safe = False\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="digest mismatch: agent/runtime.py"):
        verify_manifest(tmp_path, manifest)
