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

    def override_get_settings():
        return AppSettings(
            maintainer_token="test-secret-maintainer-token",
            paypal_webhook_id="WH-TEST-ID-123",
        )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_get_settings
    client = TestClient(app)
    yield client, TestingSession
    app.dependency_overrides.clear()


def test_maintainer_token_loaded_from_temporary_dotenv(tmp_path, monkeypatch):
    """P0 verification: Ensure MAINTAINER_TOKEN is loaded directly from .env via AppSettings,
    without monkeypatching module globals.
    """
    # 1. Create a temporary .env file
    env_file = tmp_path / ".env"
    env_file.write_text("MAINTAINER_TOKEN=token-loaded-directly-from-temporary-dotenv\n")

    # 2. Clear any active OS environment variable
    monkeypatch.delenv("MAINTAINER_TOKEN", raising=False)

    # 3. Instantiate AppSettings pointing to this temporary .env file
    dotenv_settings = AppSettings(_env_file=str(env_file))
    assert dotenv_settings.maintainer_token == "token-loaded-directly-from-temporary-dotenv"

    # 4. Wire settings into app dependency without monkeypatching module variables
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: dotenv_settings

    client = TestClient(app)

    # Setup bounty and submission
    db = TestingSession()
    bounty = BountyModel(title="Test", amount=Decimal("100.00"), currency="USD")
    db.add(bounty)
    db.commit()
    sub = SubmissionModel(
        bounty_id=bounty.id,
        contributor_email="dev@example.com",
        pr_url="https://github.com/example/repo/pull/1",
        code_diff="def ok(): pass",
    )
    db.add(sub)
    db.commit()
    sub_id = sub.id
    db.close()

    # 5. Call maintainer approval using the token loaded from .env
    resp = client.post(
        f"/submissions/{sub_id}/maintainer-approval",
        headers={"X-MAINTAINER-TOKEN": "token-loaded-directly-from-temporary-dotenv"},
        json={"approved": True, "notes": "Verified from temporary .env file"},
    )
    assert resp.status_code == 200
    assert resp.json()["maintainer_approved"] is True

    # 6. Invalid token is rejected
    bad_resp = client.post(
        f"/submissions/{sub_id}/maintainer-approval",
        headers={"X-MAINTAINER-TOKEN": "wrong-token"},
        json={"approved": True},
    )
    assert bad_resp.status_code == 403

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
            "test_suite_spec": '{"required_symbols": ["sanitize"], "forbidden_symbols": ["eval"]}',
        },
    )
    assert bounty_resp.status_code == 201
    bounty_data = bounty_resp.json()
    bounty_id = bounty_data["id"]
    assert bounty_data["amount"] == "450.00"

    # 2. SSRF Guard: Reject invalid/unauthorized PR URLs
    bad_ssrf = client.post(
        "/submissions",
        json={
            "bounty_id": bounty_id,
            "contributor_email": "attacker@evil.com",
            "pr_url": "http://169.254.169.254/latest/meta-data/",
            "code_diff": "def evil(): pass",
        },
    )
    assert bad_ssrf.status_code == 400
    assert "Invalid pr_url" in bad_ssrf.json()["detail"]

    # 3. Create Submission with stored, immutable code_diff and valid GitHub PR URL
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

    # 4. Policy evaluation fails initially
    eval_resp = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp.status_code == 200
    assert eval_resp.json()["allowed"] is False

    # 5. Run verification suite
    test_run_resp = client.post(f"/submissions/{sub_id}/run-tests")
    assert test_run_resp.status_code == 200
    assert test_run_resp.json()["all_passed"] is True

    # 6. Run AI review
    ai_rev_resp = client.post(f"/submissions/{sub_id}/ai-review")
    assert ai_rev_resp.status_code == 200
    assert ai_rev_resp.json()["verdict"] in ("approved", "changes_requested")

    # 7. Maintainer sign-off via token auth
    # Unauthenticated / invalid token fails closed with 403
    bad_auth = client.post(
        f"/submissions/{sub_id}/maintainer-approval",
        headers={"X-MAINTAINER-TOKEN": "wrong-token"},
        json={"approved": True},
    )
    assert bad_auth.status_code == 403

    # Authenticated maintainer sign-off
    good_auth = client.post(
        f"/submissions/{sub_id}/maintainer-approval",
        headers={"X-MAINTAINER-TOKEN": "test-secret-maintainer-token"},
        json={"approved": True, "notes": "Approved by maintainer."},
    )
    assert good_auth.status_code == 200
    assert good_auth.json()["maintainer_approved"] is True

    # Make review approved for final policy check
    db = SessionLocal()
    rev = db.query(ReviewModel).filter(ReviewModel.submission_id == sub_id).first()
    rev.verdict = ReviewVerdict.APPROVED.value
    db.commit()
    db.close()

    # 8. Re-evaluate policy: now allowed!
    eval_resp2 = client.post("/policy/evaluate", json={"submission_id": sub_id})
    assert eval_resp2.status_code == 200
    assert eval_resp2.json()["allowed"] is True


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


def test_api_webhook_signature_verification_fail_closed(test_client):
    """P1 verification: Webhooks must fail closed when PAYPAL_WEBHOOK_ID is unconfigured,
    and reject invalid cryptographic signatures with 401.
    """
    client, SessionLocal = test_client

    # Case 1: When PAYPAL_WEBHOOK_ID is unconfigured, reject with 503 (fail closed)
    def override_no_webhook_settings():
        return AppSettings(maintainer_token="test", paypal_webhook_id=None)

    app.dependency_overrides[get_settings] = override_no_webhook_settings
    with patch("app.main.paypal_service.webhook_id", None):
        resp_unconf = client.post(
            "/webhooks/paypal",
            json={"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "resource": {}},
            headers={"paypal-transmission-sig": "test-sig"},
        )
        assert resp_unconf.status_code == 503
        assert "PAYPAL_WEBHOOK_ID is not configured" in resp_unconf.json()["detail"]

    # Case 2: Configured webhook ID but invalid signature -> 401 Unauthorized
    def override_webhook_settings():
        return AppSettings(maintainer_token="test", paypal_webhook_id="WH-TEST-ID-123")

    app.dependency_overrides[get_settings] = override_webhook_settings
    with patch("app.main.paypal_service.webhook_id", "WH-TEST-ID-123"), \
         patch("app.main.paypal_service.verify_webhook_signature", new_callable=AsyncMock) as mock_verify:

        mock_verify.return_value = False
        resp_unauth = client.post(
            "/webhooks/paypal",
            json={"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "resource": {}},
            headers={"paypal-transmission-sig": "invalid-sig"},
        )
        assert resp_unauth.status_code == 401
        assert "Invalid PayPal webhook signature" in resp_unauth.json()["detail"]

        # Case 3: Valid signature proceeds
        mock_verify.return_value = True
        resp_auth = client.post(
            "/webhooks/paypal",
            json={"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "resource": {}},
            headers={"paypal-transmission-sig": "valid-sig"},
        )
        assert resp_auth.status_code == 200
