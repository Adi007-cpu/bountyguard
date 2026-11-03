from contextlib import asynccontextmanager
from typing import Any, List, Optional
from fastapi import Depends, FastAPI, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db, init_db
from app.models import (
    AuditEventModel,
    BountyCreate,
    BountyModel,
    BountyRead,
    PayoutExecuteRequest,
    PayoutModel,
    PayoutRead,
    PayoutSyncResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
    ReviewRead,
    SubmissionCreate,
    SubmissionModel,
    SubmissionRead,
)
from app.services.ai_reviewer import AIReviewer
from app.services.paypal import PayPalPayoutError, PayPalService
from app.services.payout_orchestrator import (
    DuplicatePayoutError,
    PayoutOrchestrator,
    PolicyDeniedError,
)
from app.services.policy import PolicyEngine
from app.services.test_runner import FixtureTestRunner, TestExecutionResult


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="BountyGuard API",
    description="Automated server-side policy validation, LLM AI code review, and secure PayPal payouts for developer bounties",
    version="0.3.0",
    lifespan=lifespan,
)

policy_engine = PolicyEngine()
paypal_service = PayPalService()
payout_orchestrator = PayoutOrchestrator(policy_engine=policy_engine, paypal_service=paypal_service)
ai_reviewer = AIReviewer()
test_runner = FixtureTestRunner()


@app.get("/")
def read_root():
    return {"status": "ok", "service": "BountyGuard API", "version": "0.3.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# --- Bounty Endpoints ---

@app.post("/bounties", response_model=BountyRead, status_code=status.HTTP_201_CREATED)
def create_bounty(bounty_in: BountyCreate, db: Session = Depends(get_db)):
    """Creates a bounty. The maintainer can optionally provide a test_suite_spec JSON."""
    bounty = BountyModel(
        title=bounty_in.title,
        description=bounty_in.description,
        amount=bounty_in.amount,
        currency=bounty_in.currency,
        test_suite_spec=bounty_in.test_suite_spec,
    )
    db.add(bounty)
    db.commit()
    db.refresh(bounty)
    return bounty


@app.get("/bounties/{bounty_id}", response_model=BountyRead)
def get_bounty(bounty_id: int, db: Session = Depends(get_db)):
    bounty = db.query(BountyModel).filter(BountyModel.id == bounty_id).first()
    if not bounty:
        raise HTTPException(status_code=404, detail="Bounty not found")
    return bounty


# --- Submission Endpoints ---

@app.post("/submissions", response_model=SubmissionRead, status_code=status.HTTP_201_CREATED)
def create_submission(sub_in: SubmissionCreate, db: Session = Depends(get_db)):
    """Creates a submission. The code_diff is frozen upon creation (from PR or verified fixture)."""
    bounty = db.query(BountyModel).filter(BountyModel.id == sub_in.bounty_id).first()
    if not bounty:
        raise HTTPException(status_code=404, detail="Bounty not found")

    submission = SubmissionModel(
        bounty_id=sub_in.bounty_id,
        contributor_email=sub_in.contributor_email,
        pr_url=sub_in.pr_url,
        code_diff=sub_in.code_diff,
        commit_sha=sub_in.commit_sha,
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    return submission


@app.get("/submissions/{submission_id}", response_model=SubmissionRead)
def get_submission(submission_id: int, db: Session = Depends(get_db)):
    submission = db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


# --- Server-Side Verification: Test Runner & AI Review ---

@app.post("/submissions/{submission_id}/run-tests", response_model=TestExecutionResult)
def run_submission_tests(
    submission_id: int,
    db: Session = Depends(get_db),
):
    """Runs automated server-side tests against the stored submission code diff and
    maintainer's bounty acceptance test spec. Does NOT accept caller-supplied test outcomes.
    """
    try:
        return test_runner.execute_and_update_submission(
            db=db,
            submission_id=submission_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/submissions/{submission_id}/ai-review", response_model=ReviewRead)
def run_submission_ai_review(
    submission_id: int,
    db: Session = Depends(get_db),
):
    """Executes real Gemini LLM structured code review + static scan on the stored submission
    and bounty spec. Fails closed if Gemini is unavailable. Does NOT accept arbitrary caller diffs.
    """
    try:
        review = ai_reviewer.evaluate_and_record_submission(
            db=db,
            submission_id=submission_id,
        )
        return review
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# --- Secure Server-Side Policy Evaluation ---

@app.post("/policy/evaluate", response_model=PolicyEvaluationResult)
def evaluate_policy(
    request: PolicyEvaluationRequest,
    db: Session = Depends(get_db),
):
    """Accepts ONLY submission_id. All policy parameters (amount, recipient email,
    CI results, AI review, maintainer approval, and duplicate payout checks)
    are loaded directly from the database server-side.
    """
    result = policy_engine.evaluate_submission(db=db, submission_id=request.submission_id)
    return result


# --- Guarded Payout Orchestration & Status Sync ---

@app.post("/payout/execute", response_model=PayoutRead)
async def execute_payout(
    request: PayoutExecuteRequest,
    db: Session = Depends(get_db),
):
    """Orchestrates guarded payout execution:
    1. Evaluates policy server-side.
    2. Enforces idempotency via persisted UUID sender_batch_id (reusing original ID on retries).
    3. Handles race conditions with DB unique constraint rollback (HTTP 409).
    4. Calls PayPal Payouts API and records PENDING status (not marked SUCCESS prematurely).
    """
    try:
        payout = await payout_orchestrator.execute_payout(db=db, submission_id=request.submission_id)
        return payout
    except PolicyDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "PolicyDenied", "reasons": e.reasons},
        )
    except DuplicatePayoutError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "DuplicatePayout", "message": str(e)},
        )
    except PayPalPayoutError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "PayPalPayoutFailed", "message": str(e)},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@app.post("/payout/{payout_id}/sync", response_model=PayoutSyncResponse)
async def sync_payout(
    payout_id: int,
    db: Session = Depends(get_db),
):
    """Queries PayPal API for batch status. Transitions payout to SUCCESS and marks
    bounty PAID only when PayPal confirms the batch is successful.
    """
    try:
        payout = await payout_orchestrator.sync_payout_status(db=db, payout_id=payout_id)
        bounty = db.query(BountyModel).filter(BountyModel.id == payout.bounty_id).first()
        return PayoutSyncResponse(
            payout_id=payout.id,
            status=payout.status,
            paypal_batch_id=payout.paypal_batch_id,
            bounty_status=bounty.status if bounty else "unknown",
            message=f"Payout {payout.id} status synced: {payout.status}",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PayPalPayoutError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/webhooks/paypal")
async def paypal_webhook(request: Request, db: Session = Depends(get_db)):
    """Receives and cryptographically verifies asynchronous PayPal webhooks
    before syncing payout status.
    """
    payload = await request.json()
    headers = dict(request.headers)

    # Cryptographically verify webhook signature when PAYPAL_WEBHOOK_ID is configured
    if paypal_service.webhook_id:
        verified = await paypal_service.verify_webhook_signature(headers=headers, body_json=payload)
        if not verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid PayPal webhook signature",
            )

    event_type = payload.get("event_type", "")
    resource = payload.get("resource", {})
    batch_header = resource.get("batch_header", {})
    payout_batch_id = batch_header.get("payout_batch_id")

    if payout_batch_id:
        payout = db.query(PayoutModel).filter(PayoutModel.paypal_batch_id == payout_batch_id).first()
        if payout:
            await payout_orchestrator.sync_payout_status(db=db, payout_id=payout.id)
            return {"status": "processed", "payout_id": payout.id, "event_type": event_type}

    return {"status": "ignored"}


# --- Audit Event Log ---

@app.get("/audit-events")
def get_audit_events(
    bounty_id: Optional[int] = None,
    submission_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    query = db.query(AuditEventModel)
    if bounty_id:
        query = query.filter(AuditEventModel.bounty_id == bounty_id)
    if submission_id:
        query = query.filter(AuditEventModel.submission_id == submission_id)
    return query.order_by(AuditEventModel.created_at.desc()).all()
