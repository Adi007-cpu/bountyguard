import json
import logging
import uuid
from typing import Optional
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AuditEventModel,
    BountyModel,
    BountyStatus,
    PayoutModel,
    PayoutStatus,
    SubmissionModel,
    SubmissionStatus,
)
from app.services.paypal import PayPalPayoutError, PayPalService
from app.services.policy import PolicyEngine

logger = logging.getLogger(__name__)


class PayoutOrchestratorError(Exception):
    pass


class PolicyDeniedError(PayoutOrchestratorError):
    def __init__(self, reasons: list[str]):
        super().__init__(f"Policy denied payout: {'; '.join(reasons)}")
        self.reasons = reasons


class DuplicatePayoutError(PayoutOrchestratorError):
    pass


class PayoutOrchestrator:
    """Coordinates policy evaluation, concurrency/idempotency protection,
    database persistence, PayPal asynchronous payouts, and status synchronization.
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        paypal_service: Optional[PayPalService] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.paypal_service = paypal_service or PayPalService()

    async def execute_payout(self, db: Session, submission_id: int) -> PayoutModel:
        # Step 1: Enforce policy evaluation server-side
        policy_result = self.policy_engine.evaluate_submission(db, submission_id)
        if not policy_result.allowed:
            audit = AuditEventModel(
                event_type="PAYOUT_DENIED_BY_POLICY",
                bounty_id=policy_result.bounty_id,
                submission_id=submission_id,
                details=json.dumps({"reasons": policy_result.reasons}),
            )
            db.add(audit)
            db.commit()
            raise PolicyDeniedError(policy_result.reasons)

        submission = (
            db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
        )
        bounty = db.query(BountyModel).filter(BountyModel.id == submission.bounty_id).first()

        # Step 2: Idempotency, concurrency, & failed payout reconciliation check
        existing_payout = (
            db.query(PayoutModel).filter(PayoutModel.bounty_id == bounty.id).first()
        )

        payout_record: PayoutModel
        sender_batch_id: str

        if existing_payout:
            # Active or completed payout cannot be repeated
            if existing_payout.status in (
                PayoutStatus.SUCCESS.value,
                PayoutStatus.PENDING.value,
                PayoutStatus.INITIATED.value,
            ):
                raise DuplicatePayoutError(
                    f"A payout is already active or completed for bounty {bounty.id} with status '{existing_payout.status}'."
                )

            # Reconcile FAILED attempt before allowing retry
            if existing_payout.status == PayoutStatus.FAILED.value:
                # If there was a PayPal batch ID on the failed attempt, verify with PayPal first
                if existing_payout.paypal_batch_id:
                    try:
                        batch_data = await self.paypal_service.get_payout_batch(existing_payout.paypal_batch_id)
                        actual_paypal_status = batch_data.get("batch_header", {}).get("batch_status", "").upper()
                        if actual_paypal_status == "SUCCESS":
                            existing_payout.status = PayoutStatus.SUCCESS.value
                            bounty.status = BountyStatus.PAID.value
                            submission.status = SubmissionStatus.PAID.value
                            db.commit()
                            # CRITICAL: Do NOT swallow DuplicatePayoutError!
                            raise DuplicatePayoutError(
                                f"Reconciliation detected previous payout already succeeded on PayPal for bounty {bounty.id} with batch {existing_payout.paypal_batch_id}."
                            )
                        elif actual_paypal_status in ("PENDING", "PROCESSING"):
                            existing_payout.status = PayoutStatus.PENDING.value
                            bounty.status = BountyStatus.PENDING_PAYOUT.value
                            db.commit()
                            # CRITICAL: Do NOT swallow DuplicatePayoutError!
                            raise DuplicatePayoutError(
                                f"Previous payout batch {existing_payout.paypal_batch_id} is currently processing on PayPal. Sync status before retrying."
                            )
                    except DuplicatePayoutError:
                        raise
                    except Exception as exc:
                        logger.warning(f"Could not query status of previous PayPal batch: {exc}")

                # CRITICAL IDEMPOTENCY RULE:
                # Keep the ORIGINAL sender_batch_id! Do NOT generate a fresh UUID.
                # PayPal explicitly guarantees idempotency per sender_batch_id within 30 days.
                sender_batch_id = existing_payout.sender_batch_id
                payout_record = existing_payout
                payout_record.status = PayoutStatus.INITIATED.value
                payout_record.error_message = None
                payout_record.amount = bounty.amount
                payout_record.recipient_email = submission.contributor_email
        else:
            # First attempt: Generate and persist a new UUID sender_batch_id
            sender_batch_id = str(uuid.uuid4())
            payout_record = PayoutModel(
                bounty_id=bounty.id,
                submission_id=submission.id,
                sender_batch_id=sender_batch_id,
                amount=bounty.amount,
                currency=bounty.currency,
                recipient_email=submission.contributor_email,
                status=PayoutStatus.INITIATED.value,
            )
            db.add(payout_record)

        audit_init = AuditEventModel(
            event_type="PAYOUT_INITIATED",
            bounty_id=bounty.id,
            submission_id=submission.id,
            details=json.dumps(
                {
                    "sender_batch_id": sender_batch_id,
                    "amount": str(bounty.amount),
                    "currency": bounty.currency,
                    "recipient_email": submission.contributor_email,
                    "is_retry": existing_payout is not None,
                }
            ),
        )
        db.add(audit_init)

        # Step 3: Atomic commit with race-condition handling (Catch concurrent IntegrityError)
        try:
            db.commit()
            db.refresh(payout_record)
        except IntegrityError as exc:
            db.rollback()
            raise DuplicatePayoutError(
                f"Concurrent payout attempt prevented: another payout is already registered for bounty {bounty.id}."
            ) from exc

        # Step 4: Dispatch payment to PayPal using the immutable sender_batch_id
        try:
            paypal_resp = await self.paypal_service.create_payout(
                sender_batch_id=sender_batch_id,
                recipient_email=submission.contributor_email,
                amount=bounty.amount,
                currency=bounty.currency,
                note=f"BountyGuard payout for #{bounty.id}: {bounty.title}",
            )

            paypal_batch_id = (
                paypal_resp.get("batch_header", {}).get("payout_batch_id")
                or paypal_resp.get("payout_batch_id")
            )
            batch_status = (
                paypal_resp.get("batch_header", {}).get("batch_status", "PENDING").upper()
            )

            payout_record.paypal_batch_id = paypal_batch_id

            if batch_status == "SUCCESS":
                payout_record.status = PayoutStatus.SUCCESS.value
                bounty.status = BountyStatus.PAID.value
                submission.status = SubmissionStatus.PAID.value
                event_type = "PAYOUT_SUCCESS"
            else:
                payout_record.status = PayoutStatus.PENDING.value
                bounty.status = BountyStatus.PENDING_PAYOUT.value
                event_type = "PAYOUT_CREATED_PENDING"

            audit_created = AuditEventModel(
                event_type=event_type,
                bounty_id=bounty.id,
                submission_id=submission.id,
                payout_id=payout_record.id,
                details=json.dumps({
                    "batch_status": batch_status,
                    "paypal_batch_id": paypal_batch_id,
                    "sender_batch_id": sender_batch_id,
                    "paypal_response": paypal_resp,
                }),
            )
            db.add(audit_created)
            db.commit()
            db.refresh(payout_record)
            return payout_record

        except Exception as exc:
            payout_record.status = PayoutStatus.FAILED.value
            payout_record.error_message = str(exc)

            audit_fail = AuditEventModel(
                event_type="PAYOUT_FAILED",
                bounty_id=bounty.id,
                submission_id=submission.id,
                payout_id=payout_record.id,
                details=json.dumps({"error": str(exc), "sender_batch_id": sender_batch_id}),
            )
            db.add(audit_fail)
            db.commit()
            db.refresh(payout_record)
            raise PayPalPayoutError(f"Payout failed for batch {sender_batch_id}: {exc}") from exc

    async def sync_payout_status(self, db: Session, payout_id: int) -> PayoutModel:
        """Fetches latest status from PayPal API and marks payout and bounty SUCCESS or FAILED."""
        payout = db.query(PayoutModel).filter(PayoutModel.id == payout_id).first()
        if not payout:
            raise ValueError(f"Payout {payout_id} not found.")

        if not payout.paypal_batch_id:
            raise ValueError(f"Payout {payout_id} has no paypal_batch_id to query.")

        batch_data = await self.paypal_service.get_payout_batch(payout.paypal_batch_id)
        batch_status = batch_data.get("batch_header", {}).get("batch_status", "").upper()

        bounty = db.query(BountyModel).filter(BountyModel.id == payout.bounty_id).first()
        submission = db.query(SubmissionModel).filter(SubmissionModel.id == payout.submission_id).first()

        if batch_status == "SUCCESS":
            payout.status = PayoutStatus.SUCCESS.value
            if bounty:
                bounty.status = BountyStatus.PAID.value
            if submission:
                submission.status = SubmissionStatus.PAID.value

            audit = AuditEventModel(
                event_type="PAYOUT_SUCCESS",
                bounty_id=payout.bounty_id,
                submission_id=payout.submission_id,
                payout_id=payout.id,
                details=json.dumps({"batch_status": batch_status, "paypal_data": batch_data}),
            )
            db.add(audit)
        elif batch_status in ("DENIED", "CANCELED", "FAILED"):
            payout.status = PayoutStatus.FAILED.value
            payout.error_message = f"PayPal reported status: {batch_status}"
            if bounty:
                bounty.status = BountyStatus.APPROVED.value

            audit = AuditEventModel(
                event_type="PAYOUT_FAILED",
                bounty_id=payout.bounty_id,
                submission_id=payout.submission_id,
                payout_id=payout.id,
                details=json.dumps({"batch_status": batch_status, "paypal_data": batch_data}),
            )
            db.add(audit)
        else:
            payout.status = PayoutStatus.PENDING.value

        db.commit()
        db.refresh(payout)
        return payout
