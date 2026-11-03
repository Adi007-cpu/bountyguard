from decimal import Decimal
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    AuditEventModel,
    BountyModel,
    BountyStatus,
    PayoutModel,
    PayoutStatus,
    ReviewModel,
    ReviewVerdict,
    ReviewerType,
    SubmissionModel,
    SubmissionStatus,
)
from app.services.policy import PolicyEngine


@pytest.fixture
def db_session():
    """In-memory SQLite database session for isolated testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def policy_engine():
    return PolicyEngine(max_auto_payout_amount=Decimal("500.00"))


def create_sample_bounty_and_submission(
    db,
    amount: Decimal = Decimal("250.00"),
    contributor_email: str = "contributor@example.com",
    ci_passed: bool = True,
    maintainer_approved: bool = True,
    ai_verdict: str = ReviewVerdict.APPROVED.value,
    bounty_status: str = BountyStatus.OPEN.value,
    code_diff: str = "def parse(): return True",
):
    bounty = BountyModel(
        title="Fix memory leak in parser",
        description="High priority parser bug",
        amount=amount,
        currency="USD",
        status=bounty_status,
    )
    db.add(bounty)
    db.commit()
    db.refresh(bounty)

    submission = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email=contributor_email,
        pr_url="https://github.com/example/repo/pull/42",
        code_diff=code_diff,
        status=SubmissionStatus.PENDING.value,
        ci_passed=ci_passed,
        maintainer_approved=maintainer_approved,
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)

    if ai_verdict:
        review = ReviewModel(
            submission_id=submission.id,
            reviewer_type=ReviewerType.AI.value,
            verdict=ai_verdict,
            score=Decimal("0.95") if ai_verdict == ReviewVerdict.APPROVED.value else Decimal("0.20"),
            summary="Automated AI review",
        )
        db.add(review)
        db.commit()

    return bounty, submission


def test_server_side_policy_approval_success(db_session, policy_engine):
    bounty, submission = create_sample_bounty_and_submission(db_session)

    result = policy_engine.evaluate_submission(db_session, submission.id)
    assert result.allowed is True
    assert len(result.reasons) == 0
    assert result.amount == Decimal("250.00")
    assert result.recipient_email == "contributor@example.com"

    # Verify audit event logged
    audit = (
        db_session.query(AuditEventModel)
        .filter(AuditEventModel.event_type == "POLICY_EVALUATION")
        .first()
    )
    assert audit is not None
    assert audit.submission_id == submission.id


def test_policy_rejection_missing_ci(db_session, policy_engine):
    bounty, submission = create_sample_bounty_and_submission(db_session, ci_passed=False)

    result = policy_engine.evaluate_submission(db_session, submission.id)
    assert result.allowed is False
    assert any("CI automated tests have not passed" in r for r in result.reasons)


def test_policy_rejection_missing_maintainer_approval(db_session, policy_engine):
    bounty, submission = create_sample_bounty_and_submission(
        db_session, maintainer_approved=False
    )

    result = policy_engine.evaluate_submission(db_session, submission.id)
    assert result.allowed is False
    assert any("Maintainer approval has not been granted" in r for r in result.reasons)


def test_policy_rejection_missing_or_rejected_ai_review(db_session, policy_engine):
    # Case 1: No AI review at all
    _, sub_no_ai = create_sample_bounty_and_submission(db_session, ai_verdict=None)
    result1 = policy_engine.evaluate_submission(db_session, sub_no_ai.id)
    assert result1.allowed is False
    assert any("AI review assessment is missing" in r for r in result1.reasons)

    # Case 2: AI review rejected
    _, sub_rejected_ai = create_sample_bounty_and_submission(
        db_session, ai_verdict=ReviewVerdict.REJECTED.value
    )
    result2 = policy_engine.evaluate_submission(db_session, sub_rejected_ai.id)
    assert result2.allowed is False
    assert any("AI review verdict is 'rejected'" in r for r in result2.reasons)


def test_policy_rejection_exceeds_amount(db_session, policy_engine):
    bounty, submission = create_sample_bounty_and_submission(
        db_session, amount=Decimal("600.00")
    )

    result = policy_engine.evaluate_submission(db_session, submission.id)
    assert result.allowed is False
    assert any("exceeds automatic payout ceiling" in r for r in result.reasons)


def test_policy_rejection_invalid_email(db_session, policy_engine):
    bounty, submission = create_sample_bounty_and_submission(
        db_session, contributor_email="invalid-email"
    )

    result = policy_engine.evaluate_submission(db_session, submission.id)
    assert result.allowed is False
    assert any("recipient email is invalid" in r for r in result.reasons)


def test_policy_rejection_duplicate_payout(db_session, policy_engine):
    bounty, submission = create_sample_bounty_and_submission(db_session)

    # Simulate existing active payout record
    existing = PayoutModel(
        bounty_id=bounty.id,
        submission_id=submission.id,
        sender_batch_id="existing-batch-uuid",
        amount=bounty.amount,
        currency="USD",
        recipient_email=submission.contributor_email,
        status=PayoutStatus.PENDING.value,
    )
    db_session.add(existing)
    db_session.commit()

    result = policy_engine.evaluate_submission(db_session, submission.id)
    assert result.allowed is False
    assert any("Duplicate payout prevented" in r for r in result.reasons)
