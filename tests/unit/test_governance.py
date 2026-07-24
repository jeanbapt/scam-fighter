import pytest
from scamfighter_core import (
    ApprovalDecision,
    AuditTampered,
    CaseState,
    Governance,
    LocalGovernance,
    Transition,
    UnauthorizedTransition,
)


def _advance(gov: LocalGovernance, case: str, *states: CaseState) -> None:
    current = gov.current_state(case)
    for nxt in states:
        gov.propose_transition(Transition(case_id=case, frm=current, to=nxt, actor="test"))
        current = nxt


def test_local_governance_satisfies_protocol():
    assert isinstance(LocalGovernance(), Governance)


def test_happy_path_reaches_executed_with_approval():
    gov = LocalGovernance()
    case = "c1"
    _advance(gov, case, CaseState.ANALYZED, CaseState.EVIDENCED, CaseState.PLANNED)
    gov.propose_transition(
        Transition(case_id=case, frm=CaseState.PLANNED, to=CaseState.APPROVED, actor="test")
    )
    gov.record_approval(ApprovalDecision(case_id=case, approved=True, approver="human"))
    gov.propose_transition(
        Transition(case_id=case, frm=CaseState.APPROVED, to=CaseState.EXECUTED, actor="test")
    )
    assert gov.current_state(case) == CaseState.EXECUTED


def test_illegal_transition_is_rejected():
    gov = LocalGovernance()
    with pytest.raises(UnauthorizedTransition):
        gov.propose_transition(
            Transition(case_id="c2", frm=CaseState.INGESTED, to=CaseState.EXECUTED, actor="test")
        )


def test_execution_requires_approval():
    gov = LocalGovernance()
    case = "c3"
    _advance(gov, case, CaseState.ANALYZED, CaseState.EVIDENCED, CaseState.PLANNED)
    gov.propose_transition(
        Transition(case_id=case, frm=CaseState.PLANNED, to=CaseState.APPROVED, actor="test")
    )
    with pytest.raises(UnauthorizedTransition):
        gov.propose_transition(
            Transition(case_id=case, frm=CaseState.APPROVED, to=CaseState.EXECUTED, actor="test")
        )


def test_audit_log_is_hash_chained():
    gov = LocalGovernance()
    case = "c4"
    _advance(gov, case, CaseState.ANALYZED, CaseState.EVIDENCED)
    log = gov.audit_log(case)
    assert len(log) == 2
    assert log[0].prev_hash == "0" * 64
    assert log[1].prev_hash == log[0].this_hash
    assert gov.verify_chain(case) is True


def test_persist_and_reload_audit(tmp_path):
    path = tmp_path / "audit.jsonl"
    gov = LocalGovernance(audit_path=path)
    case = "persist-1"
    _advance(gov, case, CaseState.ANALYZED, CaseState.EVIDENCED)
    gov.record_approval(ApprovalDecision(case_id=case, approved=True, approver="human"))
    assert path.exists()

    reloaded = LocalGovernance(audit_path=path)
    assert reloaded.current_state(case) == CaseState.EVIDENCED
    assert reloaded.verify_chain(case) is True
    assert len(reloaded.audit_log(case)) == 3
    decision = reloaded.require_approval(case)
    assert decision.approved is True
    assert decision.approver == "human"


def test_tampered_audit_fails_closed(tmp_path):
    path = tmp_path / "audit.jsonl"
    gov = LocalGovernance(audit_path=path)
    case = "tamper-1"
    _advance(gov, case, CaseState.ANALYZED)
    # Corrupt a persisted hash so reload must refuse to start.
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace(gov.audit_log(case)[0].this_hash, "0" * 64)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditTampered):
        LocalGovernance(audit_path=path)
