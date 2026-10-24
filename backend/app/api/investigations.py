from fastapi import APIRouter, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from fastapi import Depends
from app.models import SecurityFinding, SecurityInvestigation, SecurityPatchProposal, SecurityTestProposal, TestResult
from app.schemas.api_testing import TestResultRead
from app.schemas.investigation import DecisionRequest, ExecuteProposalRequest, InvestigationRead, PatchProposalRead, TestProposalRead
from app.services.ai_investigation import InvestigationError, ai_status, create_patch_proposal, create_test_proposals, execute_approved_test, refresh_patch_proposal_baseline, run_investigation


router = APIRouter(prefix="/api")


def _finding(db: Session, finding_id: str) -> SecurityFinding:
    finding = db.get(SecurityFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found.")
    return finding


def _investigation(db: Session, investigation_id: str) -> SecurityInvestigation:
    record = db.get(SecurityInvestigation, investigation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return record


def _proposal(db: Session, proposal_id: str) -> SecurityTestProposal:
    record = db.get(SecurityTestProposal, proposal_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Test proposal not found.")
    return record


def _patch(db: Session, proposal_id: str) -> SecurityPatchProposal:
    record = db.get(SecurityPatchProposal, proposal_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Patch proposal not found.")
    return record


@router.get("/ai/status")
def get_ai_status():
    return ai_status()


@router.post("/security/findings/{finding_id}/investigations", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
def start_investigation(finding_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=128), db: Session = Depends(get_db)):
    finding = _finding(db, finding_id)
    if idempotency_key and db.scalar(select(SecurityInvestigation).where(SecurityInvestigation.finding_id == finding.id, SecurityInvestigation.idempotency_key == idempotency_key)):
        return db.scalar(select(SecurityInvestigation).where(SecurityInvestigation.finding_id == finding.id, SecurityInvestigation.idempotency_key == idempotency_key))
    return run_investigation(db, finding, idempotency_key=idempotency_key)


@router.get("/security/findings/{finding_id}/investigations", response_model=list[InvestigationRead])
def list_investigations(finding_id: str, limit: int = Query(default=20, ge=1, le=100), db: Session = Depends(get_db)):
    _finding(db, finding_id)
    return db.scalars(select(SecurityInvestigation).where(SecurityInvestigation.finding_id == finding_id).order_by(SecurityInvestigation.created_at.desc()).limit(limit)).all()


@router.get("/security/investigations/{investigation_id}", response_model=InvestigationRead)
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    return _investigation(db, investigation_id)


@router.post("/security/investigations/{investigation_id}/test-proposals", response_model=list[TestProposalRead], status_code=status.HTTP_201_CREATED)
def generate_test_proposals(investigation_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=100), db: Session = Depends(get_db)):
    investigation = _investigation(db, investigation_id)
    if investigation.status != "completed":
        raise HTTPException(status_code=409, detail="A completed AI investigation is required before proposing tests.")
    finding = _finding(db, investigation.finding_id)
    try:
        return create_test_proposals(db, finding, investigation, idempotency_key=idempotency_key)
    except InvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/security/investigations/{investigation_id}/test-proposals", response_model=list[TestProposalRead])
def list_test_proposals(investigation_id: str, db: Session = Depends(get_db)):
    _investigation(db, investigation_id)
    return db.scalars(select(SecurityTestProposal).where(SecurityTestProposal.investigation_id == investigation_id).order_by(SecurityTestProposal.created_at.desc())).all()


def _decide_test(db: Session, proposal: SecurityTestProposal, decision: str, payload: DecisionRequest):
    if proposal.status == decision:
        return proposal
    if proposal.status != "proposed":
        raise HTTPException(status_code=409, detail=f"Proposal is already {proposal.status} and cannot be changed.")
    proposal.status = decision
    proposal.decision_note = payload.note[:1000] or None
    db.commit(); db.refresh(proposal)
    return proposal


@router.post("/security/test-proposals/{proposal_id}/approve", response_model=TestProposalRead)
def approve_test_proposal(proposal_id: str, payload: DecisionRequest, db: Session = Depends(get_db)):
    return _decide_test(db, _proposal(db, proposal_id), "approved", payload)


@router.post("/security/test-proposals/{proposal_id}/reject", response_model=TestProposalRead)
def reject_test_proposal(proposal_id: str, payload: DecisionRequest, db: Session = Depends(get_db)):
    return _decide_test(db, _proposal(db, proposal_id), "rejected", payload)


@router.post("/security/test-proposals/{proposal_id}/execute", response_model=TestResultRead)
def execute_test_proposal(proposal_id: str, payload: ExecuteProposalRequest, db: Session = Depends(get_db)):
    proposal = _proposal(db, proposal_id)
    try:
        return execute_approved_test(db, proposal, approve_state_changes=payload.approve_state_changes)
    except InvestigationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/security/investigations/{investigation_id}/patch-proposals", response_model=PatchProposalRead, status_code=status.HTTP_201_CREATED)
def generate_patch_proposal(investigation_id: str, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=128), db: Session = Depends(get_db)):
    investigation = _investigation(db, investigation_id)
    if investigation.status != "completed":
        raise HTTPException(status_code=409, detail="A completed AI investigation is required before proposing a patch.")
    finding = _finding(db, investigation.finding_id)
    try:
        return create_patch_proposal(db, finding, investigation, idempotency_key=idempotency_key)
    except InvestigationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/security/findings/{finding_id}/patch-proposals", response_model=list[PatchProposalRead])
def list_patch_proposals(finding_id: str, db: Session = Depends(get_db)):
    _finding(db, finding_id)
    proposals = db.scalars(select(SecurityPatchProposal).where(SecurityPatchProposal.finding_id == finding_id).order_by(SecurityPatchProposal.created_at.desc())).all()
    for proposal in proposals:
        refresh_patch_proposal_baseline(db, proposal)
    return proposals


@router.get("/security/patch-proposals/{proposal_id}", response_model=PatchProposalRead)
def get_patch_proposal(proposal_id: str, db: Session = Depends(get_db)):
    proposal = _patch(db, proposal_id)
    refresh_patch_proposal_baseline(db, proposal)
    return proposal


def _decide_patch(db: Session, proposal: SecurityPatchProposal, decision: str, payload: DecisionRequest):
    if proposal.status == decision:
        return proposal
    if proposal.status not in {"draft", "awaiting_approval"}:
        raise HTTPException(status_code=409, detail=f"Patch proposal is already {proposal.status} and cannot be changed.")
    if decision == "approved" and (proposal.status != "awaiting_approval" or proposal.applicability != "applicable"):
        raise HTTPException(status_code=409, detail="Only a patch that passed the non-mutating applicability check can be approved.")
    if decision == "approved":
        raise HTTPException(status_code=409, detail="Patch approval is unavailable until isolated patch application and baseline preservation are implemented.")
    proposal.status = decision
    proposal.decision_note = payload.note[:1000] or None
    db.commit(); db.refresh(proposal)
    return proposal


@router.post("/security/patch-proposals/{proposal_id}/approve", response_model=PatchProposalRead)
def approve_patch_proposal(proposal_id: str, payload: DecisionRequest, db: Session = Depends(get_db)):
    return _decide_patch(db, _patch(db, proposal_id), "approved", payload)


@router.post("/security/patch-proposals/{proposal_id}/reject", response_model=PatchProposalRead)
def reject_patch_proposal(proposal_id: str, payload: DecisionRequest, db: Session = Depends(get_db)):
    return _decide_patch(db, _patch(db, proposal_id), "rejected", payload)


@router.post("/security/patch-proposals/{proposal_id}/apply", status_code=status.HTTP_409_CONFLICT)
def apply_patch_proposal(proposal_id: str, db: Session = Depends(get_db)):
    proposal = _patch(db, proposal_id)
    raise HTTPException(status_code=409, detail="Patch application is unavailable: this installation has no isolated worktree/copy workflow to preserve and verify the registered project's working tree. The proposal remains review-only.")


@router.get("/security/patch-proposals/{proposal_id}/verification")
def get_patch_verification(proposal_id: str, db: Session = Depends(get_db)):
    proposal = _patch(db, proposal_id)
    return {"proposal_id": proposal.id, "status": "verification_blocked", "recorded": False, "detail": "No patch has been applied. Isolated patch execution and regression verification are not implemented in this installation; this response is an availability status, not a persisted verification record."}
