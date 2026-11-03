import asyncio
from decimal import Decimal
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
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
from app.services.paypal import (
    PayPalAuthError,
    PayPalConfigurationError,
    PayPalService,
    PayPalSettings,
)
from app.services.payout_orchestrator import (
    DuplicatePayoutError,
    PayoutOrchestrator,
    PolicyDeniedError,
)
from app.services.policy import PolicyEngine


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


def setup_submission(
    db,
    amount: Decimal = Decimal("300.00"),
    ci_passed: bool = True,
    maintainer_approved: bool = True,
    ai_verdict: str = ReviewVerdict.APPROVED.value,
    code_diff: str = "def solve_auth(): return True",
):
    bounty = BountyModel(
        title="Implement OAuth2 provider",
        description="Add OAuth2 provider support",
        amount=amount,
        currency="USD",
        status=BountyStatus.OPEN.value,
    )
    db.add(bounty)
    db.commit()
    db.refresh(bounty)

    submission = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="developer@example.com",
        pr_url="https://github.com/example/repo/pull/101",
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
            score=Decimal("0.98"),
            summary="Approved by AI review",
        )
        db.add(review)
        db.commit()

    return bounty, submission


def test_denied_policy_makes_zero_paypal_calls(db):
    """Critical verification: Denied policy decision MUST make zero calls to PayPal."""
    async def run():
        bounty, submission = setup_submission(
            db,
            ci_passed=False,
            maintainer_approved=False,
        )

        mock_paypal = AsyncMock(spec=PayPalService)
        orchestrator = PayoutOrchestrator(
            policy_engine=PolicyEngine(max_auto_payout_amount=Decimal("500.00")),
            paypal_service=mock_paypal,
        )

        with pytest.raises(PolicyDeniedError):
            await orchestrator.execute_payout(db, submission.id)

        # Assert ZERO PayPal calls were made
        assert mock_paypal.create_payout.call_count == 0
        assert mock_paypal.get_access_token.call_count == 0

        # Assert no payout record was persisted
        payout_count = db.query(PayoutModel).filter(PayoutModel.bounty_id == bounty.id).count()
        assert payout_count == 0

        # Assert audit event for policy denial was recorded
        denial_audit = (
            db.query(AuditEventModel)
            .filter(AuditEventModel.event_type == "PAYOUT_DENIED_BY_POLICY")
            .first()
        )
        assert denial_audit is not None
        assert denial_audit.submission_id == submission.id

    asyncio.run(run())


def test_duplicate_payout_makes_zero_paypal_calls(db):
    """Verification: Duplicate payout attempts MUST be blocked with zero calls to PayPal."""
    async def run():
        bounty, submission = setup_submission(db)

        # Pre-existing active payout
        existing_payout = PayoutModel(
            bounty_id=bounty.id,
            submission_id=submission.id,
            sender_batch_id=str(uuid.uuid4()),
            amount=bounty.amount,
            currency="USD",
            recipient_email=submission.contributor_email,
            status=PayoutStatus.PENDING.value,
        )
        db.add(existing_payout)
        db.commit()

        mock_paypal = AsyncMock(spec=PayPalService)
        orchestrator = PayoutOrchestrator(
            policy_engine=PolicyEngine(),
            paypal_service=mock_paypal,
        )

        with pytest.raises((PolicyDeniedError, DuplicatePayoutError)):
            await orchestrator.execute_payout(db, submission.id)

        # Assert ZERO PayPal calls
        assert mock_paypal.create_payout.call_count == 0

    asyncio.run(run())


def test_successful_guarded_payout_with_async_pending_and_sync(db):
    """Verification: Payout creation sets PENDING status (not marked SUCCESS prematurely).
    Transitions to SUCCESS and marks bounty PAID only after batch status verification.
    """
    async def run():
        bounty, submission = setup_submission(db, amount=Decimal("350.00"))

        mock_paypal = AsyncMock(spec=PayPalService)
        # PayPal asynchronously responds with PENDING
        mock_paypal.create_payout.return_value = {
            "batch_header": {
                "payout_batch_id": "PAYPAL-BATCH-998877",
                "batch_status": "PENDING",
            }
        }
        mock_paypal.get_payout_batch.return_value = {
            "batch_header": {
                "payout_batch_id": "PAYPAL-BATCH-998877",
                "batch_status": "SUCCESS",
            }
        }

        orchestrator = PayoutOrchestrator(
            policy_engine=PolicyEngine(max_auto_payout_amount=Decimal("1000.00")),
            paypal_service=mock_paypal,
        )

        # 1. Execute payout creation
        payout = await orchestrator.execute_payout(db, submission.id)

        # Assert created with PENDING (not SUCCESS prematurely!)
        assert payout.status == PayoutStatus.PENDING.value
        assert payout.paypal_batch_id == "PAYPAL-BATCH-998877"

        # Bounty is PENDING_PAYOUT, not PAID yet!
        db.refresh(bounty)
        assert bounty.status == BountyStatus.PENDING_PAYOUT.value

        # 2. Sync payout status after clearing
        synced_payout = await orchestrator.sync_payout_status(db, payout.id)
        assert synced_payout.status == PayoutStatus.SUCCESS.value

        # Now bounty is marked PAID!
        db.refresh(bounty)
        assert bounty.status == BountyStatus.PAID.value

        # Verify audit trail
        audit_events = db.query(AuditEventModel).filter(AuditEventModel.bounty_id == bounty.id).all()
        event_types = [e.event_type for e in audit_events]
        assert "PAYOUT_INITIATED" in event_types
        assert "PAYOUT_CREATED_PENDING" in event_types
        assert "PAYOUT_SUCCESS" in event_types

    asyncio.run(run())


def test_concurrent_integrity_error_handled_cleanly(db):
    """Verification: Concurrent race condition collision on commit is caught and rolled back."""
    async def run():
        bounty, submission = setup_submission(db)

        mock_paypal = AsyncMock(spec=PayPalService)
        orchestrator = PayoutOrchestrator(
            policy_engine=PolicyEngine(),
            paypal_service=mock_paypal,
        )

        # First commit succeeds (policy audit event), second commit triggers concurrent collision
        with patch.object(db, "commit", side_effect=[None, IntegrityError("UNIQUE constraint failed", {}, None)]):
            with pytest.raises(DuplicatePayoutError) as exc_info:
                await orchestrator.execute_payout(db, submission.id)

            assert "Concurrent payout attempt prevented" in str(exc_info.value)
            mock_paypal.create_payout.assert_not_called()

    asyncio.run(run())


def test_reconcile_and_retry_failed_payout_keeps_same_sender_batch_id(db):
    """P0 verification: Retrying a failed attempt MUST preserve the original sender_batch_id
    for PayPal idempotency, rather than generating a fresh UUID.
    """
    async def run():
        bounty, submission = setup_submission(db)
        original_sender_batch_id = "original-batch-uuid-12345"

        # Setup an existing FAILED payout record
        failed_payout = PayoutModel(
            bounty_id=bounty.id,
            submission_id=submission.id,
            sender_batch_id=original_sender_batch_id,
            amount=bounty.amount,
            currency="USD",
            recipient_email=submission.contributor_email,
            status=PayoutStatus.FAILED.value,
            error_message="Network 503 timeout during initial dispatch",
        )
        db.add(failed_payout)
        db.commit()

        mock_paypal = AsyncMock(spec=PayPalService)
        mock_paypal.create_payout.return_value = {
            "batch_header": {
                "payout_batch_id": "RETRY-PAYPAL-BATCH-123",
                "batch_status": "PENDING",
            }
        }

        orchestrator = PayoutOrchestrator(
            policy_engine=PolicyEngine(),
            paypal_service=mock_paypal,
        )

        retried_payout = await orchestrator.execute_payout(db, submission.id)

        # MUST preserve the original sender_batch_id for PayPal idempotency
        assert retried_payout.sender_batch_id == original_sender_batch_id
        assert retried_payout.status == PayoutStatus.PENDING.value
        assert retried_payout.paypal_batch_id == "RETRY-PAYPAL-BATCH-123"

        # Verify PayPal was called with the SAME sender_batch_id
        assert mock_paypal.create_payout.call_count == 1
        call_kwargs = mock_paypal.create_payout.call_args.kwargs
        assert call_kwargs["sender_batch_id"] == original_sender_batch_id

    asyncio.run(run())


def test_reconcile_failed_payout_detects_already_successful_batch_without_swallowing(db):
    """P0 verification: If PayPal reports the old batch as SUCCESS, DuplicatePayoutError
    MUST be raised (NOT swallowed), and retry must be aborted with zero PayPal create calls.
    """
    async def run():
        bounty, submission = setup_submission(db)
        sender_batch_id = "uncertain-batch-id-999"

        # Setup payout that was recorded as FAILED locally due to network uncertainty
        failed_payout = PayoutModel(
            bounty_id=bounty.id,
            submission_id=submission.id,
            sender_batch_id=sender_batch_id,
            paypal_batch_id="PAYPAL-BATCH-DISPATCHED",
            amount=bounty.amount,
            currency="USD",
            recipient_email=submission.contributor_email,
            status=PayoutStatus.FAILED.value,
        )
        db.add(failed_payout)
        db.commit()

        mock_paypal = AsyncMock(spec=PayPalService)
        # PayPal reveals that the batch actually SUCCEEDED on their end!
        mock_paypal.get_payout_batch.return_value = {
            "batch_header": {
                "payout_batch_id": "PAYPAL-BATCH-DISPATCHED",
                "batch_status": "SUCCESS",
            }
        }

        orchestrator = PayoutOrchestrator(
            policy_engine=PolicyEngine(),
            paypal_service=mock_paypal,
        )

        # Must raise DuplicatePayoutError, NOT proceed to create a second payout
        with pytest.raises(DuplicatePayoutError) as exc_info:
            await orchestrator.execute_payout(db, submission.id)

        assert "already succeeded on PayPal" in str(exc_info.value)
        # Zero create_payout calls
        mock_paypal.create_payout.assert_not_called()

        # Payout and bounty updated to SUCCESS / PAID
        db.refresh(failed_payout)
        db.refresh(bounty)
        assert failed_payout.status == PayoutStatus.SUCCESS.value
        assert bounty.status == BountyStatus.PAID.value

    asyncio.run(run())


def test_database_unique_constraint_on_bounty_payout(db):
    """Verification: Enforce one payout per bounty with DB unique constraint."""
    bounty, submission = setup_submission(db)

    p1 = PayoutModel(
        bounty_id=bounty.id,
        submission_id=submission.id,
        sender_batch_id=str(uuid.uuid4()),
        amount=Decimal("100.00"),
        currency="USD",
        recipient_email="dev1@example.com",
        status=PayoutStatus.SUCCESS.value,
    )
    db.add(p1)
    db.commit()

    p2 = PayoutModel(
        bounty_id=bounty.id,
        submission_id=submission.id,
        sender_batch_id=str(uuid.uuid4()),
        amount=Decimal("100.00"),
        currency="USD",
        recipient_email="dev2@example.com",
        status=PayoutStatus.SUCCESS.value,
    )
    db.add(p2)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_paypal_service_fail_fast_on_missing_credentials():
    """Verification: Fail fast when credentials or access tokens are missing."""
    async def run():
        service = PayPalService(
            PayPalSettings(
                paypal_client_id="",
                paypal_client_secret="",
            )
        )

        with pytest.raises(PayPalConfigurationError):
            await service.get_access_token()

    asyncio.run(run())


def test_paypal_service_fail_fast_on_empty_token():
    """Verification: Fail fast when token response is missing access_token."""
    async def run():
        service = PayPalService(
            PayPalSettings(
                paypal_client_id="valid_client_id",
                paypal_client_secret="valid_client_secret",
            )
        )

        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"access_token": ""}  # Empty token!
            mock_post.return_value = mock_response

            with pytest.raises(PayPalAuthError):
                await service.get_access_token()

    asyncio.run(run())
