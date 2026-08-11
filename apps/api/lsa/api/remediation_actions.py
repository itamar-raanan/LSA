from fastapi import APIRouter, Depends, HTTPException, Query

from lsa.dependencies import current_user
from lsa.models import User
from lsa.schemas import RemediationActionResponse
from lsa.services.remediation_catalog import (
    action_supports,
    latest_remediation_actions,
    remediation_action,
)


router = APIRouter(prefix="/remediation-actions", tags=["remediation action catalog"])


@router.get("", response_model=list[RemediationActionResponse])
def list_remediation_actions(
    control_id: str | None = None,
    os_family: str | None = None,
    os_version: str | None = None,
    _: User = Depends(current_user),
) -> list[RemediationActionResponse]:
    if (os_family is None) != (os_version is None):
        raise HTTPException(status_code=422, detail="os_family and os_version must be provided together")
    actions = list(latest_remediation_actions())
    if control_id is not None:
        actions = [action for action in actions if control_id in action.control_ids]
    if os_family is not None and os_version is not None:
        actions = [action for action in actions if action_supports(action, os_family, os_version)]
    return actions


@router.get("/{action_id}", response_model=RemediationActionResponse)
def get_remediation_action(
    action_id: str,
    version: int | None = Query(default=None, ge=1),
    _: User = Depends(current_user),
) -> RemediationActionResponse:
    action = remediation_action(action_id, version)
    if action is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    return action
