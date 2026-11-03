from contextlib import asynccontextmanager
import json
import logging
import os
import re
from typing import Any, List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
import httpx
from sqlalchemy.orm import Session

from app.database import get_db, init_db
from app.models import (
    AuditEventModel,
    BountyCreate,
    BountyModel,
    BountyRead,
    MaintainerApprovalRequest,
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
from app.seed import seed_demo_scenarios
from app.services.ai_reviewer import AIReviewer
from app.services.paypal import PayPalPayoutError, PayPalService, PayPalWebhookVerificationError
from app.services.payout_orchestrator import (
    DuplicatePayoutError,
    PayoutOrchestrator,
    PolicyDeniedError,
)
from app.services.policy import PolicyEngine
from app.services.test_runner import FixtureTestRunner, TestExecutionResult

logger = logging.getLogger(__name__)

# Strict regex matching GitHub PR URLs to prevent SSRF
GITHUB_PR_REGEX = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)/pull/([0-9]+)/?$"
)

# Maintainer token from environment (Fail closed: No insecure defaults!)
MAINTAINER_TOKEN = os.getenv("MAINTAINER_TOKEN")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="BountyGuard API",
    description="Automated server-side policy validation, LLM AI code review, and secure PayPal payouts for developer bounties",
    version="0.4.0",
    lifespan=lifespan,
)

policy_engine = PolicyEngine()
paypal_service = PayPalService()
payout_orchestrator = PayoutOrchestrator(policy_engine=policy_engine, paypal_service=paypal_service)
ai_reviewer = AIReviewer()
test_runner = FixtureTestRunner()


@app.get("/")
def read_root():
    return {
        "status": "ok",
        "service": "BountyGuard API",
        "version": "0.4.0",
        "dashboard_url": "/dashboard",
        "docs_url": "/docs",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# --- Bounty Endpoints ---

@app.post("/bounties", response_model=BountyRead, status_code=status.HTTP_201_CREATED)
def create_bounty(bounty_in: BountyCreate, db: Session = Depends(get_db)):
    """Creates a bounty. Maintainers can define acceptance criteria (required symbols, forbidden symbols, min score)."""
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


@app.get("/bounties", response_model=List[BountyRead])
def list_bounties(db: Session = Depends(get_db)):
    return db.query(BountyModel).order_by(BountyModel.id.desc()).all()


@app.get("/bounties/{bounty_id}", response_model=BountyRead)
def get_bounty(bounty_id: int, db: Session = Depends(get_db)):
    bounty = db.query(BountyModel).filter(BountyModel.id == bounty_id).first()
    if not bounty:
        raise HTTPException(status_code=404, detail="Bounty not found")
    return bounty


# --- Submission Endpoints ---

@app.post("/submissions", response_model=SubmissionRead, status_code=status.HTTP_201_CREATED)
async def create_submission(sub_in: SubmissionCreate, db: Session = Depends(get_db)):
    """Creates a submission. Validates PR URL to prevent SSRF and freezes the immutable code diff."""
    bounty = db.query(BountyModel).filter(BountyModel.id == sub_in.bounty_id).first()
    if not bounty:
        raise HTTPException(status_code=404, detail="Bounty not found")

    code_diff = sub_in.code_diff
    diff_source = "preseeded_fixture"

    # Validate pr_url format strictly to prevent SSRF attacks
    pr_match = GITHUB_PR_REGEX.match(sub_in.pr_url.strip())
    if not pr_match:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid pr_url. Must be a GitHub pull request URL (https://github.com/<owner>/<repo>/pull/<number>).",
        )

    # If code_diff was not supplied, fetch diff safely from verified GitHub host
    if not code_diff and pr_match:
        owner, repo, pr_number = pr_match.groups()
        diff_url = f"https://patch-diff.githubusercontent.com/raw/{owner}/{repo}/pull/{pr_number}.diff"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(diff_url, headers={"User-Agent": "BountyGuard-Agent"})
                if resp.status_code == 200 and resp.text.strip():
                    code_diff = resp.text
                    diff_source = "github_pr_diff"
        except Exception as e:
            logger.warning(f"Error fetching GitHub PR diff: {e}")

    if not code_diff or not code_diff.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve code diff from GitHub. Please provide code_diff explicitly (or use demo fixture).",
        )

    submission = SubmissionModel(
        bounty_id=sub_in.bounty_id,
        contributor_email=sub_in.contributor_email,
        pr_url=sub_in.pr_url,
        code_diff=code_diff,
        commit_sha=sub_in.commit_sha,
        diff_source=diff_source,
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    return submission


@app.get("/submissions", response_model=List[SubmissionRead])
def list_submissions(bounty_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(SubmissionModel)
    if bounty_id:
        query = query.filter(SubmissionModel.bounty_id == bounty_id)
    return query.order_by(SubmissionModel.id.desc()).all()


@app.get("/submissions/{submission_id}", response_model=SubmissionRead)
def get_submission(submission_id: int, db: Session = Depends(get_db)):
    submission = db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


# --- Maintainer Approval Endpoint ---

@app.post("/submissions/{submission_id}/maintainer-approval", response_model=SubmissionRead)
def set_maintainer_approval(
    submission_id: int,
    approval: MaintainerApprovalRequest,
    x_maintainer_token: Optional[str] = Header(None, alias="X-MAINTAINER-TOKEN"),
    db: Session = Depends(get_db),
):
    """Protected maintainer sign-off endpoint. Fails closed if MAINTAINER_TOKEN is unset."""
    if not MAINTAINER_TOKEN or not MAINTAINER_TOKEN.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Maintainer authentication is not configured on this server (MAINTAINER_TOKEN unset).",
        )

    if not x_maintainer_token or x_maintainer_token != MAINTAINER_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing X-MAINTAINER-TOKEN header.",
        )

    submission = db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    submission.maintainer_approved = approval.approved

    audit = AuditEventModel(
        event_type="MAINTAINER_APPROVAL",
        bounty_id=submission.bounty_id,
        submission_id=submission.id,
        details=json.dumps(
            {
                "approved": approval.approved,
                "notes": approval.notes,
                "token_authenticated": True,
            }
        ),
    )
    db.add(audit)
    db.commit()
    db.refresh(submission)
    return submission


# --- Server-Side Verification: Test Runner & AI Review ---

@app.post("/submissions/{submission_id}/run-tests", response_model=TestExecutionResult)
def run_submission_tests(
    submission_id: int,
    db: Session = Depends(get_db),
):
    """Executes server-side verification suite (diff integrity, AST syntax parsing,
    static security guardrails, required symbols, and forbidden symbols).
    Does NOT accept arbitrary untrusted code execution from caller.
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
    and bounty spec. Fails closed if Gemini is unavailable. Does NOT accept caller-supplied diffs.
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
    CI results, AI review, min_score, maintainer approval, and duplicate payout checks)
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
    2. Preserves original sender_batch_id idempotency key on retries.
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
    """Receives and cryptographically verifies asynchronous PayPal webhooks.
    Fails closed: Rejects requests if PAYPAL_WEBHOOK_ID is unconfigured or signature is invalid.
    """
    payload = await request.json()
    headers = dict(request.headers)

    # Fail closed: Reject if PAYPAL_WEBHOOK_ID is unconfigured
    if not paypal_service.webhook_id or not paypal_service.webhook_id.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PAYPAL_WEBHOOK_ID is not configured on this server; unverified webhooks rejected.",
        )

    try:
        verified = await paypal_service.verify_webhook_signature(headers=headers, body_json=payload)
    except PayPalWebhookVerificationError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid PayPal webhook signature.",
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


# --- Demo Seeding Endpoint ---

@app.post("/seed")
def seed_demo(db: Session = Depends(get_db)):
    """Seeds the three demo scenarios without pre-approvals so the full live flow can be demonstrated."""
    summary = seed_demo_scenarios(db)
    return {"status": "seeded", "scenarios": summary}


# --- Interactive Mission Control Dashboard ---

@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Renders the secure BountyGuard Mission Control dashboard."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BountyGuard | AI Guarded PayPal Payouts</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #0b0f19; color: #f3f4f6; }
    pre, code { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="min-h-screen flex flex-col">
  <!-- Top Navigation -->
  <header class="border-b border-gray-800 bg-gray-900/60 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
    <div class="flex items-center space-x-3">
      <div class="h-10 w-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
        <i class="fa-solid fa-shield-halved text-white text-lg"></i>
      </div>
      <div>
        <h1 class="text-xl font-bold bg-gradient-to-r from-blue-400 via-indigo-300 to-white bg-clip-text text-transparent">BountyGuard</h1>
        <p class="text-xs text-gray-400">Guarded AI Code Review & Autonomous PayPal Payouts</p>
      </div>
    </div>
    <div class="flex items-center space-x-3">
      <button onclick="triggerSeed()" class="px-4 py-2 bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/30 text-indigo-300 rounded-lg text-sm font-semibold transition flex items-center space-x-2">
        <i class="fa-solid fa-wand-magic-sparkles"></i>
        <span>Seed 3 Demo Scenarios</span>
      </button>
      <a href="/docs" target="_blank" class="px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition">
        <i class="fa-solid fa-book-open mr-1"></i> API Docs
      </a>
    </div>
  </header>

  <!-- Main Content Layout -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- Left Column: Active Bounties & Submissions -->
    <div class="space-y-6">
      <div class="bg-gray-900/80 border border-gray-800 rounded-2xl p-5 shadow-xl">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-base font-bold text-gray-200 flex items-center gap-2">
            <i class="fa-solid fa-coins text-amber-400"></i> Bounties
          </h2>
          <span id="bounty-count" class="text-xs bg-gray-800 px-2 py-0.5 rounded text-gray-400 font-mono">0 active</span>
        </div>
        <div id="bounties-list" class="space-y-3 max-h-[360px] overflow-y-auto pr-1">
          <p class="text-xs text-gray-500">Loading bounties...</p>
        </div>
      </div>

      <div class="bg-gray-900/80 border border-gray-800 rounded-2xl p-5 shadow-xl">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-base font-bold text-gray-200 flex items-center gap-2">
            <i class="fa-solid fa-code-pull-request text-blue-400"></i> Submissions
          </h2>
          <span id="sub-count" class="text-xs bg-gray-800 px-2 py-0.5 rounded text-gray-400 font-mono">0 total</span>
        </div>
        <div id="submissions-list" class="space-y-3 max-h-[360px] overflow-y-auto pr-1">
          <p class="text-xs text-gray-500">Loading submissions...</p>
        </div>
      </div>
    </div>

    <!-- Center Column: Active Inspection, Verification & Policy Guard -->
    <div class="space-y-6">
      <div class="bg-gray-900/80 border border-gray-800 rounded-2xl p-5 shadow-xl">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-base font-bold text-gray-200 flex items-center gap-2">
            <i class="fa-solid fa-microchip text-indigo-400"></i> Active Evaluation
          </h2>
          <span id="active-sub-id" class="text-xs font-mono bg-blue-900/40 text-blue-300 border border-blue-800 px-2 py-0.5 rounded">None Selected</span>
        </div>

        <div id="inspector-panel" class="space-y-4">
          <div class="bg-gray-950 rounded-xl p-3 border border-gray-800/80 text-xs text-gray-400">
            Select a submission from the left to inspect its frozen code diff, run the verification suite, trigger Gemini AI review, and maintainer sign-off.
          </div>
        </div>
      </div>

      <!-- Policy Engine Guardrails Checklist -->
      <div class="bg-gray-900/80 border border-gray-800 rounded-2xl p-5 shadow-xl">
        <h2 class="text-base font-bold text-gray-200 mb-4 flex items-center gap-2">
          <i class="fa-solid fa-scale-balanced text-emerald-400"></i> Policy Guardrails Checklist
        </h2>
        <div id="policy-checklist" class="space-y-2.5 text-sm">
          <div class="flex items-center justify-between p-2.5 bg-gray-950/60 rounded-lg border border-gray-800/60">
            <span class="text-gray-300 flex items-center gap-2"><i class="fa-solid fa-vial text-gray-500"></i> Verification Suite (AST, Syntax & Symbols)</span>
            <span id="badge-ci" class="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">Pending</span>
          </div>
          <div class="flex items-center justify-between p-2.5 bg-gray-950/60 rounded-lg border border-gray-800/60">
            <span class="text-gray-300 flex items-center gap-2"><i class="fa-solid fa-robot text-gray-500"></i> Gemini 3.8 Flash AI Review</span>
            <span id="badge-ai" class="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">Pending</span>
          </div>
          <div class="flex items-center justify-between p-2.5 bg-gray-950/60 rounded-lg border border-gray-800/60">
            <span class="text-gray-300 flex items-center gap-2"><i class="fa-solid fa-user-check text-gray-500"></i> Maintainer Approval</span>
            <span id="badge-maintainer" class="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">Pending</span>
          </div>
          <div class="flex items-center justify-between p-2.5 bg-gray-950/60 rounded-lg border border-gray-800/60">
            <span class="text-gray-300 flex items-center gap-2"><i class="fa-solid fa-fingerprint text-gray-500"></i> Duplicate / Idempotency Check</span>
            <span id="badge-dup" class="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">Passed</span>
          </div>
        </div>

        <div class="mt-5 pt-4 border-t border-gray-800 flex items-center justify-between">
          <button id="btn-evaluate" onclick="evaluateActivePolicy()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-600 text-white font-medium rounded-lg text-sm transition">
            Evaluate Policy
          </button>
          <button id="btn-payout" onclick="executePayout()" disabled class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-800 disabled:text-gray-600 text-white font-medium rounded-lg text-sm transition flex items-center gap-1.5">
            <i class="fa-brands fa-paypal"></i> Execute Payout
          </button>
        </div>
      </div>
    </div>

    <!-- Right Column: Audit Event Timeline -->
    <div class="space-y-6">
      <div class="bg-gray-900/80 border border-gray-800 rounded-2xl p-5 shadow-xl flex flex-col h-full">
        <div class="flex justify-between items-center mb-4">
          <h2 class="text-base font-bold text-gray-200 flex items-center gap-2">
            <i class="fa-solid fa-list-check text-purple-400"></i> Audit Event Timeline
          </h2>
          <button onclick="loadAuditEvents()" class="text-xs text-gray-400 hover:text-white transition">
            <i class="fa-solid fa-arrows-rotate"></i>
          </button>
        </div>
        <div id="audit-timeline" class="space-y-3 overflow-y-auto max-h-[760px] pr-1 flex-1">
          <p class="text-xs text-gray-500">Loading audit trail...</p>
        </div>
      </div>
    </div>
  </main>

  <script>
    let activeSubmissionId = null;
    let activeBountyId = null;

    function escapeHtml(text) {
      if (text === null || text === undefined) return '';
      return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    async function loadBounties() {
      const res = await fetch('/bounties');
      const bounties = await res.json();
      document.getElementById('bounty-count').innerText = `${bounties.length} active`;
      const container = document.getElementById('bounties-list');
      container.innerHTML = bounties.map(b => `
        <div class="p-3 bg-gray-950 hover:bg-gray-800/80 rounded-xl border border-gray-800 cursor-pointer transition" onclick="selectBounty(${b.id})">
          <div class="flex justify-between items-start">
            <h3 class="text-sm font-semibold text-gray-200 line-clamp-1">${escapeHtml(b.title)}</h3>
            <span class="text-xs font-mono text-emerald-400 font-bold">$${escapeHtml(b.amount)}</span>
          </div>
          <div class="flex justify-between items-center mt-2 text-xs text-gray-500">
            <span>#${escapeHtml(b.id)}</span>
            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
              b.status === 'paid' ? 'bg-emerald-900/50 text-emerald-400' :
              b.status === 'pending_payout' ? 'bg-amber-900/50 text-amber-400' : 'bg-gray-800 text-gray-400'
            }">${escapeHtml(b.status)}</span>
          </div>
        </div>
      `).join('') || '<p class="text-xs text-gray-500">No bounties found. Click Seed.</p>';
    }

    async function loadSubmissions() {
      const res = await fetch('/submissions');
      const subs = await res.json();
      document.getElementById('sub-count').innerText = `${subs.length} total`;
      const container = document.getElementById('submissions-list');
      container.innerHTML = subs.map(s => `
        <div class="p-3 bg-gray-950 hover:bg-gray-800/80 rounded-xl border border-gray-800 cursor-pointer transition ${activeSubmissionId === s.id ? 'ring-2 ring-blue-500' : ''}" onclick="selectSubmission(${s.id})">
          <div class="flex justify-between items-start">
            <span class="text-xs font-mono text-blue-400 font-semibold">PR #${escapeHtml(s.id)}</span>
            <span class="text-xs font-mono text-gray-400 line-clamp-1">${escapeHtml(s.contributor_email)}</span>
          </div>
          <div class="flex items-center gap-2 mt-2">
            <span class="text-[10px] px-1.5 py-0.5 rounded ${s.ci_passed ? 'bg-emerald-900/40 text-emerald-300' : 'bg-red-900/40 text-red-300'}">CI: ${s.ci_passed ? 'PASS' : 'FAIL'}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded ${s.maintainer_approved ? 'bg-emerald-900/40 text-emerald-300' : 'bg-amber-900/40 text-amber-300'}">Approval: ${s.maintainer_approved ? 'YES' : 'NO'}</span>
          </div>
        </div>
      `).join('') || '<p class="text-xs text-gray-500">No submissions found. Click Seed.</p>';
    }

    async function selectSubmission(id) {
      activeSubmissionId = id;
      document.getElementById('active-sub-id').innerText = `Submission #${id}`;
      const res = await fetch(`/submissions/${id}`);
      const sub = await res.json();
      activeBountyId = sub.bounty_id;

      const inspector = document.getElementById('inspector-panel');
      inspector.innerHTML = `
        <div class="space-y-3">
          <div class="flex justify-between items-center text-xs">
            <span class="text-gray-400">Contributor:</span>
            <span class="font-mono text-gray-200">${escapeHtml(sub.contributor_email)}</span>
          </div>
          <div class="flex justify-between items-center text-xs">
            <span class="text-gray-400">Diff Source:</span>
            <span class="font-mono px-2 py-0.5 rounded bg-gray-800 text-indigo-300">${escapeHtml(sub.diff_source)}</span>
          </div>
          <div>
            <div class="flex justify-between text-xs text-gray-400 mb-1">
              <span>Frozen Code Diff:</span>
              <span class="font-mono text-[10px]">SHA: ${escapeHtml(sub.commit_sha) || 'N/A'}</span>
            </div>
            <pre class="bg-gray-950 p-2.5 rounded-lg border border-gray-800 text-[11px] text-gray-300 max-h-36 overflow-auto font-mono whitespace-pre">${escapeHtml(sub.code_diff)}</pre>
          </div>
          <div class="grid grid-cols-2 gap-2 pt-2">
            <button onclick="runVerificationSuite(${id})" class="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-xs font-semibold rounded-lg text-gray-200 transition">
              Run Verification Suite
            </button>
            <button onclick="runAIReview(${id})" class="px-3 py-1.5 bg-indigo-900/40 hover:bg-indigo-900/60 border border-indigo-700 text-xs font-semibold rounded-lg text-indigo-200 transition">
              Run Gemini AI Review
            </button>
          </div>
          <div class="pt-2">
            <button onclick="approveMaintainer(${id})" class="w-full px-3 py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-700 text-xs font-semibold rounded-lg text-emerald-300 transition">
              Maintainer Sign-Off (Token Auth)
            </button>
          </div>
        </div>
      `;

      updateChecklistUI(sub);
      loadSubmissions();
    }

    function updateChecklistUI(sub) {
      const ciBadge = document.getElementById('badge-ci');
      ciBadge.innerText = sub.ci_passed ? 'PASS' : 'FAIL';
      ciBadge.className = `text-xs font-mono px-2 py-0.5 rounded ${sub.ci_passed ? 'bg-emerald-900/60 text-emerald-300' : 'bg-red-900/60 text-red-300'}`;

      const maintBadge = document.getElementById('badge-maintainer');
      maintBadge.innerText = sub.maintainer_approved ? 'APPROVED' : 'PENDING';
      maintBadge.className = `text-xs font-mono px-2 py-0.5 rounded ${sub.maintainer_approved ? 'bg-emerald-900/60 text-emerald-300' : 'bg-amber-900/60 text-amber-300'}`;

      document.getElementById('btn-payout').disabled = true;
    }

    async function runVerificationSuite(id) {
      const res = await fetch(`/submissions/${id}/run-tests`, { method: 'POST' });
      const data = await res.json();
      alert(`Verification Suite Result:\nAll Passed: ${data.all_passed}\nPassed: ${data.passed_tests}/${data.total_tests}\nLogs: ${data.logs}`);
      await selectSubmission(id);
      loadAuditEvents();
    }

    async function runAIReview(id) {
      const res = await fetch(`/submissions/${id}/ai-review`, { method: 'POST' });
      const data = await res.json();
      const badgeAi = document.getElementById('badge-ai');
      badgeAi.innerText = data.verdict.toUpperCase();
      badgeAi.className = `text-xs font-mono px-2 py-0.5 rounded ${data.verdict === 'approved' ? 'bg-emerald-900/60 text-emerald-300' : 'bg-red-900/60 text-red-300'}`;
      alert(`Gemini AI Review Result:\nVerdict: ${data.verdict}\nScore: ${data.score}\nSummary: ${data.summary}`);
      loadAuditEvents();
    }

    async function approveMaintainer(id) {
      // Prompt user with a blank input (Fail closed, no hardcoded defaults)
      const token = prompt('Enter X-MAINTAINER-TOKEN:');
      if (!token) return;
      const res = await fetch(`/submissions/${id}/maintainer-approval`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-MAINTAINER-TOKEN': token
        },
        body: JSON.stringify({ approved: true, notes: 'Approved via BountyGuard Mission Control' })
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Authentication failed: ${err.detail || 'Invalid Maintainer Token'}`);
        return;
      }
      alert('Maintainer approval signed off successfully!');
      await selectSubmission(id);
      loadAuditEvents();
    }

    async function evaluateActivePolicy() {
      if (!activeSubmissionId) { alert('Select a submission first.'); return; }
      const res = await fetch('/policy/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ submission_id: activeSubmissionId })
      });
      const data = await res.json();
      if (data.allowed) {
        alert('Policy evaluation: ALLOWED! Guardrails satisfied.');
        document.getElementById('btn-payout').disabled = false;
      } else {
        alert(`Policy evaluation: DENIED!\nReasons:\n- ${data.reasons.join('\n- ')}`);
        document.getElementById('btn-payout').disabled = true;
      }
      loadAuditEvents();
    }

    async function executePayout() {
      if (!activeSubmissionId) return;
      const res = await fetch('/payout/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ submission_id: activeSubmissionId })
      });
      const data = await res.json();
      if (res.ok) {
        alert(`Payout Initiated! Status: ${data.status}\nBatch ID: ${data.sender_batch_id}\nSyncing with PayPal Sandbox...`);
        const syncRes = await fetch(`/payout/${data.id}/sync`, { method: 'POST' });
        const syncData = await syncRes.json();
        alert(`Sync Complete!\nStatus: ${syncData.status}\nBounty Status: ${syncData.bounty_status}`);
      } else {
        alert(`Payout Failed: ${JSON.stringify(data.detail)}`);
      }
      loadBounties();
      loadSubmissions();
      loadAuditEvents();
    }

    async function loadAuditEvents() {
      const res = await fetch('/audit-events');
      const events = await res.json();
      const container = document.getElementById('audit-timeline');
      container.innerHTML = events.slice(0, 25).map(e => `
        <div class="p-2.5 bg-gray-950 rounded-lg border border-gray-800/80 text-xs font-mono space-y-1">
          <div class="flex justify-between items-center">
            <span class="text-indigo-400 font-bold">${escapeHtml(e.event_type)}</span>
            <span class="text-gray-500 text-[10px]">${new Date(e.created_at).toLocaleTimeString()}</span>
          </div>
          <p class="text-gray-400 text-[11px] line-clamp-2">${escapeHtml(e.details)}</p>
        </div>
      `).join('') || '<p class="text-xs text-gray-500">No events logged yet.</p>';
    }

    async function triggerSeed() {
      const res = await fetch('/seed', { method: 'POST' });
      const data = await res.json();
      alert('Seeded 3 Scenarios (bounties & raw submissions only, without pre-approvals):\n1. Good Submission (RateLimiter)\n2. Broken Submission (StreamParser)\n3. Malicious Submission (WebhookDispatcher)\n\nClick the verification and AI review buttons to run the live workflow!');
      loadBounties();
      loadSubmissions();
      loadAuditEvents();
    }

    loadBounties();
    loadSubmissions();
    loadAuditEvents();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
