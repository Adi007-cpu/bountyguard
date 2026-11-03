import json
from decimal import Decimal
from typing import Optional
from sqlalchemy.orm import Session

from app.models import (
    AuditEventModel,
    BountyModel,
    BountyStatus,
    PayoutModel,
    PayoutStatus,
    PolicyEvaluationResult,
    ReviewModel,
    ReviewerType,
    ReviewVerdict,
    SubmissionModel,
)


class PolicyEngine:
    """Server-side policy validation engine.
    
    Evaluates trusted database records (bounty, submission, CI execution, AI reviews,
    maintainer approvals, duplicate payout constraints, and ceiling limits).
    Client inputs cannot influence approval rules.
    """

    def __init__(self, max_auto_payout_amount: Decimal = Decimal("1000.00")):
        self.max_auto_payout_amount = max_auto_payout_amount

    def evaluate_submission(
        self, db: Session, submission_id: int, record_audit: bool = True
    ) -> PolicyEvaluationResult:
        reasons: list[str] = []

        submission = (
            db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
        )
        if not submission:
            reasons.append(f"Submission with ID {submission_id} does not exist.")
            return PolicyEvaluationResult(
                allowed=False,
                submission_id=submission_id,
                reasons=reasons,
            )

        bounty = db.query(BountyModel).filter(BountyModel.id == submission.bounty_id).first()
        if not bounty:
            reasons.append(f"Associated bounty {submission.bounty_id} does not exist.")
            return PolicyEvaluationResult(
                allowed=False,
                submission_id=submission_id,
                reasons=reasons,
            )

        # 1. Bounty status check
        if bounty.status == BountyStatus.PAID.value:
            reasons.append("Bounty is already marked as PAID.")
        elif bounty.status == BountyStatus.PENDING_PAYOUT.value:
            reasons.append("Bounty payout is currently in progress.")
        elif bounty.status == BountyStatus.CANCELLED.value:
            reasons.append("Bounty has been cancelled.")

        # 2. Duplicate Payout / Idempotency Check
        existing_payout = (
            db.query(PayoutModel)
            .filter(
                PayoutModel.bounty_id == bounty.id,
                PayoutModel.status.in_([
                    PayoutStatus.SUCCESS.value,
                    PayoutStatus.PENDING.value,
                    PayoutStatus.INITIATED.value,
                ]),
            )
            .first()
        )
        if existing_payout:
            reasons.append(
                f"Duplicate payout prevented: Payout {existing_payout.id} (status: {existing_payout.status}) "
                f"already exists for bounty {bounty.id} with batch ID {existing_payout.sender_batch_id}."
            )

        # 3. Maintainer approval check
        if not submission.maintainer_approved:
            reasons.append("Maintainer approval has not been granted for this submission.")

        # 4. CI automated test pass check
        if not submission.ci_passed:
            reasons.append("CI automated tests have not passed for this submission.")

        # 5. AI review verification
        ai_review = (
            db.query(ReviewModel)
            .filter(
                ReviewModel.submission_id == submission.id,
                ReviewModel.reviewer_type == ReviewerType.AI.value,
            )
            .order_by(ReviewModel.created_at.desc())
            .first()
        )
        if not ai_review:
            reasons.append("Structured AI review assessment is missing.")
        elif ai_review.verdict != ReviewVerdict.APPROVED.value:
            reasons.append(
                f"AI review verdict is '{ai_review.verdict}': {ai_review.summary}"
            )

        # 6. Recipient email validation
        if not submission.contributor_email or "@" not in submission.contributor_email:
            reasons.append("Contributor recipient email is invalid.")

        # 7. Financial guardrails (ceiling and positive amount)
        if bounty.amount <= Decimal("0.00"):
            reasons.append("Bounty amount must be greater than zero.")
        elif bounty.amount > self.max_auto_payout_amount:
            reasons.append(
                f"Bounty amount ${bounty.amount:.2f} exceeds automatic payout ceiling of ${self.max_auto_payout_amount:.2f}."
            )

        allowed = len(reasons) == 0

        # Record policy evaluation in AuditEvent
        if record_audit:
            audit = AuditEventModel(
                event_type="POLICY_EVALUATION",
                bounty_id=bounty.id,
                submission_id=submission.id,
                details=json.dumps(
                    {
                        "allowed": allowed,
                        "reasons": reasons,
                        "bounty_amount": str(bounty.amount),
                        "recipient_email": submission.contributor_email,
                        "ci_passed": submission.ci_passed,
                        "maintainer_approved": submission.maintainer_approved,
                    }
                ),
            )
            db.add(audit)
            db.commit()

        return PolicyEvaluationResult(
            allowed=allowed,
            submission_id=submission.id,
            bounty_id=bounty.id,
            amount=bounty.amount,
            currency=bounty.currency,
            recipient_email=submission.contributor_email,
            reasons=reasons,
        )
