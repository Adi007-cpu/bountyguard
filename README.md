# BountyGuard

Automated server-side policy guardrails, Gemini LLM AI code review, and secure asynchronous PayPal payouts for developer bounties.

## Architecture & Security Highlights

- **Server-Side Trust Boundary & Immutable Submissions**: Submissions store the immutable code diff (`code_diff`) and commit SHA upon creation. Neither `/submissions/{id}/run-tests` nor `/submissions/{id}/ai-review` accept caller-supplied code diffs or test contexts.
- **SSRF-Protected PR Diff Fetching**: Automated pull request diff fetching strictly validates URLs matching `https://github.com/<owner>/<repo>/pull/<number>` before resolving patches, preventing Server-Side Request Forgery.
- **Real Gemini LLM Code Review**: Uses the Google GenAI SDK (`gemini-3.8-flash`) with structured JSON schema output (`AIReviewAssessment`). Evaluates the submitted code against the bounty's title, description, and requirements, while retaining a deterministic static analysis pre-check for dangerous operations (`eval`, `os.system`, shell execution). Fails closed if the LLM is unavailable.
- **Maintainer Acceptance Criteria Enforcement**: Maintainers specify `required_symbols`, `forbidden_symbols`, and `min_score` upon creating bounties. The verification suite enforces symbol constraints, and the policy engine enforces quality score thresholds.
- **Protected Maintainer Sign-Off**: The `POST /submissions/{id}/maintainer-approval` endpoint requires authentication via `X-MAINTAINER-TOKEN` and fails closed if unconfigured.
- **Asynchronous PayPal Payout Lifecycle**: Payouts are created in `PENDING` status. Funds and bounties are never marked `PAID` prematurely—only after verifying batch status via `POST /payout/{id}/sync` or receiving PayPal webhooks (`POST /webhooks/paypal`).
- **Fail-Closed Webhook Verification**: Rejects unsigned or unverified webhook events with `HTTP 503` if `PAYPAL_WEBHOOK_ID` is unconfigured, or `HTTP 401` if signature verification fails.
- **Concurrency & Idempotency Protection**: Every payout generates and persists a UUID `sender_batch_id`. Race conditions between concurrent requests are caught via database unique constraints (`IntegrityError`), rolled back, and reported cleanly as HTTP 409 Conflict.
- **Failed Attempt Reconciliation**: Failed payout retries preserve the original `sender_batch_id` for PayPal 30-day idempotency, verifying previous status on PayPal before proceeding.
- **Strict Financial Precision**: All financial amounts use Python `Decimal` and SQLAlchemy `Numeric(12, 2)`.
- **Zero PayPal Calls on Policy Denial**: Policy failure immediately aborts with zero calls to PayPal.
- **Complete Audit Trail**: Every policy check, test run, AI review, and payout state transition is recorded in `audit_events`.
- **XSS-Protected Mission Control Dashboard**: Real-time visual dashboard at `/dashboard` with complete HTML escaping across all dynamic fields.

---

## Project Structure

```
bountyguard/
├── app/
│   ├── database.py                 # SQLAlchemy engine, session factory, and DB initialization
│   ├── main.py                     # FastAPI application endpoints, dashboard & lifespan handler
│   ├── models.py                   # SQLAlchemy ORM models and Pydantic schemas (Decimal)
│   ├── seed.py                     # Seed script for the 3 demo scenarios
│   └── services/
│       ├── ai_reviewer.py          # Gemini LLM code reviewer + static security scanner
│       ├── paypal.py               # PayPal client with batch creation, query, timeouts & webhooks
│       ├── payout_orchestrator.py  # Concurrency protection, async payout lifecycle & status sync
│       ├── policy.py               # Server-side policy engine enforcing min_score & guardrails
│       └── test_runner.py          # Verification suite (AST, syntax, required & forbidden symbols)
├── tests/
│   ├── test_ai_and_runner.py       # Tests for Gemini LLM structured review & AST runner
│   ├── test_api.py                 # FastAPI integration, anti-tampering, SSRF guard & webhooks
│   ├── test_payout.py              # Zero-call denial, concurrency race & retry reconciliation
│   ├── test_policy.py              # Server-side policy rule unit tests
│   └── test_scenarios.py           # End-to-end tests for the 3 seeded scenarios
├── .env.example                    # Template for environment variables
├── .gitignore                      # Git ignored patterns
├── LICENSE                         # MIT License
├── pyproject.toml                  # Python package manifest
├── requirements.txt                # Production dependencies
├── requirements-dev.txt            # Development dependencies
└── README.md
```

---

## Getting Started

### 1. Environment Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements-dev.txt
# or: pip install -e ".[dev]"
```

Configure environment variables:

```bash
cp .env.example .env
```

```env
PAYPAL_CLIENT_ID=your_sandbox_client_id
PAYPAL_CLIENT_SECRET=your_sandbox_client_secret
PAYPAL_WEBHOOK_ID=your_sandbox_webhook_id
PAYPAL_API_BASE=https://api-m.sandbox.paypal.com
DATABASE_URL=sqlite:///./bountyguard.db
GEMINI_API_KEY=your_gemini_api_key
MAINTAINER_TOKEN=your_secure_maintainer_token
APP_ENV=development
```

---

### 2. Running Tests

Run the full pytest suite (27 unit, integration, concurrency, and scenario tests):

```bash
pytest
```

---

### 3. Running the Server & Mission Control

Start the local development server:

```bash
uvicorn app.main:app --reload
```

- **Interactive Mission Control Dashboard**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
