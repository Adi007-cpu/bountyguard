from decimal import Decimal
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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


@pytest.fixture
def test_client():
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

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client, TestingSession
    app.dependency_overrides.clear()


def test_api_bounty_and_submission_lifecycle(test_client):
    client, SessionLocal = test_client

    # 1. Create Bounty with maintainer acceptance test spec
    bounty_resp = client.post(
        "/bounties",
        json={
            "title": "Fix critical security flaw",
            "description": "SQL injection vulnerability patch",
            "amount": 450.00,
            "currency": "USD",
            "test_suite_spec": '{"required_symbols": ["sanitize"]}',
        },
    )
    assert bounty_resp.status_code == 201
    bounty_data = bounty_resp.json()
    bounty_id = bounty_data["id"]
    assert bounty_data["amount"] == "450.00"
    assert bounty_data["test_suite_spec"] is not None

    # 2. Create Submission with stored, immutable code_diff
    sub_resp = client.post(
        "/submissions",
        json={
            "bounty_id": bounty_id,
            "contributor_email": "security_pro@example.com",
            "pr_url": "https://github.com/example/repo/pull/12",
            "code_diff": "def sanitize(query: str): return query.replace(\"'\", \"\")",
        },
    )
    assert sub_resp.status_code == 201
    sub_data = sub_resp.json()
    sub_id = sub_data["id"]
    assert sub_data["ci_passed"] is False
    assert sub_data["maintainer_approved"] is False
    assert "sanitize" in sub_data["code_diff"]

    # 3. Policy evaluation fails initially because server-side checks aren't met
    eval_resp = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["allowed"] is False
    assert len(eval_data["reasons"]) > 0

    # 4. Caller CANNOT spoof amount, CI or approvals via client request
    spoof_attempt = client.post(
        "/policy/evaluate",
        json={
            "submission_id": sub_id,
            "amount": 10.00,
            "ci_passed": True,
            "maintainer_approved": True,
        },
    )
    assert spoof_attempt.status_code == 200
    assert spoof_attempt.json()["allowed"] is False

    # 5. Run test runner (takes NO caller context; evaluates stored code diff against maintainer spec)
    test_run_resp = client.post(f"/submissions/{sub_id}/run-tests")
    assert test_run_resp.status_code == 200
    assert test_run_resp.json()["all_passed"] is True

    # 6. Run AI review (fails closed if GEMINI_API_KEY is unset, requiring maintainer human review)
    ai_rev_resp = client.post(f"/submissions/{sub_id}/ai-review")
    assert ai_rev_resp.status_code == 200
    # In test environment without Gemini key, it fails closed to changes_requested
    assert ai_rev_resp.json()["verdict"] in ("approved", "changes_requested")

    # Maintainer reviews and approves submission directly in DB
    db = SessionLocal()
    rev = db.query(ReviewModel).filter(ReviewModel.submission_id == sub_id).first()
    rev.verdict = ReviewVerdict.APPROVED.value
    sub = db.query(SubmissionModel).filter(SubmissionModel.id == sub_id).first()
    sub.maintainer_approved = True
    db.commit()
    db.close()

    # 7. Re-evaluate policy: now allowed!
    eval_resp2 = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp2.status_code == 200
    eval_data2 = eval_resp2.json()
    assert eval_data2["allowed"] is True
    assert eval_data2["amount"] == "450.00"
    assert eval_data2["recipient_email"] == "security_pro@example.com"


def test_api_payout_guarded_endpoint_and_sync(test_client):
    client, SessionLocal = test_client

    db = SessionLocal()
    bounty = BountyModel(
        title="Speed up search query",
        description="Index query optimization",
        amount=Decimal("200.00"),
        currency="USD",
        status=BountyStatus.OPEN.value,
    )
    db.add(bounty)
    db.commit()

    sub = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="fastcoder@example.com",
        pr_url="https://github.com/example/repo/pull/34",
        code_diff="def speedup(): return True",
        ci_passed=True,
        maintainer_approved=True,
    )
    db.add(sub)
    db.commit()

    rev = ReviewModel(
        submission_id=sub.id,
        reviewer_type=ReviewerType.AI.value,
        verdict=ReviewVerdict.APPROVED.value,
        score=Decimal("0.96"),
        summary="Clean patch",
    )
    db.add(rev)
    db.commit()
    sub_id = sub.id
    bounty_id = bounty.id
    db.close()

    with patch("app.main.payout_orchestrator.paypal_service.create_payout", new_callable=AsyncMock) as mock_payout, \
         patch("app.main.payout_orchestrator.paypal_service.get_payout_batch", new_callable=AsyncMock) as mock_batch:

        mock_payout.return_value = {
            "batch_header": {
                "payout_batch_id": "BATCH-XYZ-12345",
                "batch_status": "PENDING",
            }
        }
        mock_batch.return_value = {
            "batch_header": {
                "payout_batch_id": "BATCH-XYZ-12345",
                "batch_status": "SUCCESS",
            }
        }

        # 1. Execute payout creation (sets status to PENDING)
        resp = client.post("/payout/execute", json={"submission_id": sub_id})
        assert resp.status_code == 200
        data = resp.json()
        payout_id = data["id"]
        assert data["status"] == "pending"
        assert data["paypal_batch_id"] == "BATCH-XYZ-12345"
        assert mock_payout.call_count == 1

        bounty_chk = client.get(f"/bounties/{bounty_id}").json()
        assert bounty_chk["status"] == "pending_payout"

        # 2. Attempt duplicate payout -> blocked by policy / duplicate guard
        dup_resp = client.post("/payout/execute", json={"submission_id": sub_id})
        assert dup_resp.status_code in (400, 409)
        assert mock_payout.call_count == 1

        # 3. Synchronize status with PayPal
        sync_resp = client.post(f"/payout/{payout_id}/sync")
        assert sync_resp.status_code == 200
        sync_data = sync_resp.json()
        assert sync_data["status"] == "success"
        assert sync_data["bounty_status"] == "paid"

        bounty_after_sync = client.get(f"/bounties/{bounty_id}").json()
        assert bounty_after_sync["status"] == "paid"


def test_api_webhook_signature_verification(test_client):
    """P1 verification: Webhooks must verify cryptographic signature before processing."""
    client, SessionLocal = test_client

    with patch("app.main.paypal_service.webhook_id", "WH-TEST-ID-123"), \
         patch("app.main.paypal_service.verify_webhook_signature", new_callable=AsyncMock) as mock_verify:

        # Case 1: Invalid signature returns 401 Unauthorized
        mock_verify.return_value = False
        resp_unauth = client.post(
            "/webhooks/paypal",
            json={"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "resource": {}},
            headers={"paypal-transmission-sig": "invalid-sig"},
        )
        assert resp_unauth.status_code == 401
        assert "Invalid PayPal webhook signature" in resp_unauth.json()["detail"]

        # Case 2: Valid signature proceeds
        mock_verify.return_value = True
        resp_auth = client.post(
            "/webhooks/paypal",
            json={"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "resource": {}},
            headers={"paypal-transmission-sig": "valid-sig"},
        )
        assert resp_auth.status_code == 200
