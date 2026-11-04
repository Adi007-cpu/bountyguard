import asyncio
from decimal import Decimal
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import AppSettings, get_settings
from app.database import Base, get_db
from app.main import app
from app.models import (
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
from app.seed import BROKEN_DIFF, GOOD_DIFF, MALICIOUS_DIFF
from app.services.paypal import PayPalService
from app.services.payout_orchestrator import PayoutOrchestrator, PolicyDeniedError
from app.services.policy import PolicyEngine


@pytest.fixture
def test_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    def override_settings():
        return AppSettings(maintainer_token="scenario-maintainer-secret")

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings
    client = TestClient(app)
    session = TestingSession()
    yield client, session
    session.close()
    app.dependency_overrides.clear()


def test_scenario_1_good_submission_end_to_end(test_env):
    """Scenario 1: Good submission -> Gemini approves -> maintainer approves ->
    payout becomes PENDING -> sync shows SUCCESS.
    """
    client, db = test_env

    # 1. Maintainer creates Bounty with acceptance criteria
    bounty_resp = client.post(
        "/bounties",
        json={
            "title": "Implement RateLimiter middleware",
            "description": "Sliding window rate limiter with check_rate_limit",
            "amount": 350.00,
            "currency": "USD",
            "acceptance_criteria": {
                "required_symbols": ["RateLimiter", "check_rate_limit"],
            },
        },
    )
    assert bounty_resp.status_code == 201
    bounty_id = bounty_resp.json()["id"]

    # 2. Contributor submits valid PR with code diff
    sub_resp = client.post(
        "/submissions",
        json={
            "bounty_id": bounty_id,
            "contributor_email": "top_dev@example.com",
            "pr_url": "https://github.com/example/repo/pull/101",
            "code_diff": GOOD_DIFF,
            "commit_sha": "a1b2c3d4e5f67890",
        },
    )
    assert sub_resp.status_code == 201
    sub_id = sub_resp.json()["id"]

    # 3. Verification suite runs (AST + syntax + maintainer required symbols)
    test_run_resp = client.post(f"/submissions/{sub_id}/run-tests")
    assert test_run_resp.status_code == 200
    assert test_run_resp.json()["all_passed"] is True

    # 4. Gemini AI Review evaluates and approves
    # Mock LLM response to simulate Gemini 3.8 Flash approval
    with patch("app.main.ai_reviewer._get_client") as mock_get_client:
        from unittest.mock import MagicMock
        mock_gemini = MagicMock()
        mock_interaction = MagicMock()
        mock_interaction.output_text = """{
            "verdict": "approved",
            "score": 0.98,
            "summary": "Gemini 3.8 Flash: Clean implementation matching all acceptance criteria.",
            "security_checks_passed": true,
            "spec_requirements_met": true
        }"""
        mock_gemini.interactions.create.return_value = mock_interaction
        mock_get_client.return_value = mock_gemini

        ai_resp = client.post(f"/submissions/{sub_id}/ai-review")
        assert ai_resp.status_code == 200
        assert ai_resp.json()["verdict"] == "approved"

    # 5. Maintainer approves via authenticated token endpoint
    approval_resp = client.post(
        f"/submissions/{sub_id}/maintainer-approval",
        headers={"X-MAINTAINER-TOKEN": "scenario-maintainer-secret"},
        json={"approved": True, "notes": "LGTM, verified in staging environment."},
    )
    assert approval_resp.status_code == 200
    assert approval_resp.json()["maintainer_approved"] is True

    # 6. Policy evaluation succeeds
    eval_resp = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp.status_code == 200
    assert eval_resp.json()["allowed"] is True

    # 7. Execute Payout -> becomes PENDING on PayPal
    with patch("app.main.payout_orchestrator.paypal_service.create_payout", new_callable=AsyncMock) as mock_payout, \
         patch("app.main.payout_orchestrator.paypal_service.get_payout_batch", new_callable=AsyncMock) as mock_batch:

        mock_payout.return_value = {
            "batch_header": {
                "payout_batch_id": "PAYPAL-BATCH-SCENARIO-1",
                "batch_status": "PENDING",
            }
        }
        mock_batch.return_value = {
            "batch_header": {
                "payout_batch_id": "PAYPAL-BATCH-SCENARIO-1",
                "batch_status": "SUCCESS",
            }
        }

        payout_resp = client.post("/payout/execute", json={"submission_id": sub_id})
        assert payout_resp.status_code == 200
        payout_data = payout_resp.json()
        payout_id = payout_data["id"]
        # Asynchronously PENDING
        assert payout_data["status"] == "pending"
        assert mock_payout.call_count == 1

        # 8. Sync status -> SUCCESS & Bounty PAID
        sync_resp = client.post(f"/payout/{payout_id}/sync")
        assert sync_resp.status_code == 200
        sync_data = sync_resp.json()
        assert sync_data["status"] == "success"
        assert sync_data["bounty_status"] == "paid"

        # Verify bounty in DB
        bounty_final = client.get(f"/bounties/{bounty_id}").json()
        assert bounty_final["status"] == "paid"


def test_scenario_2_broken_submission_zero_paypal_calls(test_env):
    """Scenario 2: Broken submission -> test/AST/spec check fails -> zero PayPal calls."""
    client, db = test_env

    # 1. Maintainer creates Bounty
    bounty_resp = client.post(
        "/bounties",
        json={
            "title": "StreamParser chunk parsing",
            "description": "Stream parser buffer management",
            "amount": 200.00,
            "currency": "USD",
            "acceptance_criteria": {
                "required_symbols": ["stream_parse", "cleanup_buffer"],
            },
        },
    )
    bounty_id = bounty_resp.json()["id"]

    # 2. Contributor submits broken syntax
    sub_resp = client.post(
        "/submissions",
        json={
            "bounty_id": bounty_id,
            "contributor_email": "broken_dev@example.com",
            "pr_url": "https://github.com/example/repo/pull/102",
            "code_diff": BROKEN_DIFF,
        },
    )
    sub_id = sub_resp.json()["id"]

    # 3. Verification suite runs and FAILS on AST syntax validation
    test_run_resp = client.post(f"/submissions/{sub_id}/run-tests")
    assert test_run_resp.status_code == 200
    assert test_run_resp.json()["all_passed"] is False

    # 4. Policy evaluation DENIED
    eval_resp = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp.status_code == 200
    assert eval_resp.json()["allowed"] is False
    assert any("CI automated tests have not passed" in r for r in eval_resp.json()["reasons"])

    # 5. Payout attempt is BLOCKED -> ZERO PayPal calls made
    with patch("app.main.payout_orchestrator.paypal_service.create_payout", new_callable=AsyncMock) as mock_payout:
        payout_attempt = client.post("/payout/execute", json={"submission_id": sub_id})
        assert payout_attempt.status_code == 400
        assert mock_payout.call_count == 0


def test_scenario_3_malicious_submission_zero_paypal_calls(test_env):
    """Scenario 3: Malicious submission -> static scan or Gemini rejects -> zero PayPal calls."""
    client, db = test_env

    # 1. Maintainer creates Bounty
    bounty_resp = client.post(
        "/bounties",
        json={
            "title": "Webhook dispatch utility",
            "description": "Safe webhook payload delivery",
            "amount": 500.00,
            "currency": "USD",
        },
    )
    bounty_id = bounty_resp.json()["id"]

    # 2. Contributor submits malicious code (os.system exfiltration)
    sub_resp = client.post(
        "/submissions",
        json={
            "bounty_id": bounty_id,
            "contributor_email": "adversary@evil.org",
            "pr_url": "https://github.com/example/repo/pull/103",
            "code_diff": MALICIOUS_DIFF,
        },
    )
    sub_id = sub_resp.json()["id"]

    # 3. Verification suite runs and catches dangerous pattern
    test_run_resp = client.post(f"/submissions/{sub_id}/run-tests")
    assert test_run_resp.status_code == 200
    assert test_run_resp.json()["all_passed"] is False

    # 4. AI review runs: Static scan immediately catches os.system and REJECTS
    ai_resp = client.post(f"/submissions/{sub_id}/ai-review")
    assert ai_resp.status_code == 200
    assert ai_resp.json()["verdict"] == "rejected"
    assert "Static security scan failed" in ai_resp.json()["summary"]

    # 5. Policy evaluation DENIED
    eval_resp = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp.status_code == 200
    assert eval_resp.json()["allowed"] is False
    assert any("AI review verdict is 'rejected'" in r for r in eval_resp.json()["reasons"])

    # 6. Payout attempt is BLOCKED -> ZERO PayPal calls made
    with patch("app.main.payout_orchestrator.paypal_service.create_payout", new_callable=AsyncMock) as mock_payout:
        payout_attempt = client.post("/payout/execute", json={"submission_id": sub_id})
        assert payout_attempt.status_code == 400
        assert mock_payout.call_count == 0


def test_scenario_4_ai_approves_but_policy_blocks_without_maintainer_approval(test_env):
    """Scenario 4: AI approval is insufficient; maintainer sign-off is still required.

    This is the core safety guarantee: policy remains the authority that permits
    money movement, even after a valid submission passes verification and AI review.
    """
    client, _ = test_env

    # 1. A maintainer defines a bounty with deterministic acceptance criteria.
    bounty_resp = client.post(
        "/bounties",
        json={
            "title": "Implement RateLimiter middleware",
            "description": "Sliding window rate limiter with check_rate_limit.",
            "amount": 350.00,
            "currency": "USD",
            "acceptance_criteria": {
                "required_symbols": ["RateLimiter", "check_rate_limit"],
                "min_score": 0.90,
            },
        },
    )
    assert bounty_resp.status_code == 201
    bounty_id = bounty_resp.json()["id"]

    # 2. The contributor submits a valid implementation.
    sub_resp = client.post(
        "/submissions",
        json={
            "bounty_id": bounty_id,
            "contributor_email": "approved_by_ai@example.com",
            "pr_url": "https://github.com/example/repo/pull/104",
            "code_diff": GOOD_DIFF,
            "commit_sha": "c4d5e6f7a8b9c0d1",
        },
    )
    assert sub_resp.status_code == 201
    sub_id = sub_resp.json()["id"]

    # 3. Deterministic verification passes.
    verification = client.post(f"/submissions/{sub_id}/run-tests")
    assert verification.status_code == 200
    assert verification.json()["all_passed"] is True

    # 4. Gemini recommends approval with a score that exceeds the maintainer threshold.
    from unittest.mock import MagicMock

    mock_gemini = MagicMock()
    mock_interaction = MagicMock()
    mock_interaction.output_text = """{
        "verdict": "approved",
        "score": 0.95,
        "summary": "The implementation meets the bounty requirements.",
        "security_checks_passed": true,
        "spec_requirements_met": true
    }"""
    mock_gemini.interactions.create.return_value = mock_interaction

    with patch("app.main.ai_reviewer._get_client", return_value=mock_gemini):
        ai_review = client.post(f"/submissions/{sub_id}/ai-review")
    assert ai_review.status_code == 200
    assert ai_review.json()["verdict"] == "approved"
    assert ai_review.json()["score"] == "0.95"

    # 5. Deliberately skip maintainer sign-off.
    submission = client.get(f"/submissions/{sub_id}").json()
    assert submission["maintainer_approved"] is False

    # 6. The deterministic policy blocks the payout despite an AI approval.
    evaluation = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert evaluation.status_code == 200
    assert evaluation.json()["allowed"] is False
    assert any(
        "Maintainer approval has not been granted" in reason
        for reason in evaluation.json()["reasons"]
    )

    # 7. A denied policy decision makes zero PayPal calls.
    with patch(
        "app.main.payout_orchestrator.paypal_service.create_payout",
        new_callable=AsyncMock,
    ) as mock_payout:
        payout_attempt = client.post("/payout/execute", json={"submission_id": sub_id})
    assert payout_attempt.status_code == 400
    assert mock_payout.call_count == 0
