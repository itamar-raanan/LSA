"""Validation-only remediation execution protocol contracts.

This module deliberately has no task creation or dispatch behavior.
"""

from __future__ import annotations

from typing import Any

from lsa.models import PlatformChangeSigningKey, PlatformCommandSigningKey, RemediationChangeSet
from lsa.schemas import RemediationExecutionContractPreview
from lsa.services.platform_command_trust import sign_platform_envelope


def change_signing_trust_descriptor(key: PlatformChangeSigningKey) -> dict[str, Any]:
    return {
        "key_id": key.id,
        "algorithm": "Ed25519",
        "public_key": key.public_key,
        "fingerprint": key.fingerprint,
    }


def build_validation_contract(
    *,
    change_set: RemediationChangeSet,
    change_signing_key: PlatformChangeSigningKey,
    platform_command_key: PlatformCommandSigningKey,
    target: dict[str, Any],
    actions: list[dict[str, Any]],
) -> RemediationExecutionContractPreview:
    signing_trust = change_signing_trust_descriptor(change_signing_key)
    endorsement = {
        "schema_version": "1.0",
        "kind": "change-signing-key-endorsement",
        "tenant_id": change_set.tenant_id,
        "purpose": "remediation-validation",
        "platform_command_key_id": platform_command_key.id,
        "change_signing_key": signing_trust,
    }
    return RemediationExecutionContractPreview(
        change_set={
            "change_set_id": change_set.id,
            "tenant_id": change_set.tenant_id,
            "digest": change_set.digest,
            "payload": change_set.payload,
            "signature": change_set.signature,
            "signing_key": signing_trust,
        },
        platform_endorsement=endorsement,
        platform_endorsement_signature=sign_platform_envelope(
            platform_command_key, endorsement
        ),
        target=target,
        actions=actions,
    )
