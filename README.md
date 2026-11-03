# BountyGuard

Automated server-side policy guardrails, Gemini LLM AI code review, and secure asynchronous PayPal payouts for developer bounties.

## Architecture & Security Highlights

- **Server-Side Trust Boundary & Immutable Submissions**: Submissions store the immutable code diff (`code_diff`) and commit SHA upon creation. Neither `/submissions/{id}/run-tests` nor `/submissions/{id}/ai-review` accept caller-supplied code diffs or test contexts.
- **Real Gemini LLM Code Review**: Uses the Google GenAI SDK (`gemini-3.8-flash`) with structured JSON schema output (`AIReviewAssessment`). Evaluates the submitted code against the bounty's title, description, and requirements, while retaining a deterministic static analysis pre-check for dangerous operations (`eval`, `os.system`, shell execution).
- **Asynchronous PayPal Payout Lifecycle**: Payouts are created in `PENDING` status. Funds and bounties are never marked `PAID` prematurely—only after verifying batch status via `POST /payout/{id}/sync` or receiving PayPal webhooks (`POST /webhooks/paypal`).
- **Concurrency & Idempotency Protection**: Every payout generates and persists a UUID `sender_batch_id`. Race conditions between concurrent requests are caught via database unique constraints (`IntegrityError`), rolled back, and reported cleanly as HTTP 409 Conflict.
- **Reconciliation & Retries**: Failed attempts are verified against PayPal before allowing a safe retry with a refreshed idempotency key without violating database unique constraints.
- **Strict Financial Precision**: All financial amounts use Python `Decimal` and SQLAlchemy `Numeric(12, 2)`.
- **Zero PayPal Calls on Policy Denial**: Policy failure immediately aborts with zero calls to PayPal.
- **Complete Audit Trail**: Every policy check, test run, AI review, and payout state transition is recorded in `audit_events`.

---

## Project Structure

```
bountyguard/
├── app/
│   ├── database.py                 # SQLAlchemy engine, session factory, and DB initialization
│   ├── main.py                     # FastAPI application endpoints & lifespan handler
│   ├── models.py                   # SQLAlchemy ORM models and Pydantic schemas (Decimal)
│   └── services/
│       ├── ai_reviewer.py          # Gemini LLM code reviewer + static security scanner
│       ├── paypal.py               # PayPal client with batch creation, query, and timeouts
│       ├── payout_orchestrator.py  # Concurrency protection, async payout lifecycle & status sync
│       ├── policy.py               # Server-side policy engine
│       └── test_runner.py          # Automated AST & syntax test execution runner
├── tests/
│   ├── test_ai_and_runner.py       # Tests for Gemini LLM structured review & AST runner
│   ├── test_api.py                 # FastAPI integration, anti-tampering & async sync tests
│   ├── test_payout.py              # Zero-call denial, concurrency race & retry reconciliation
│   └── test_policy.py              # Server-side policy rule unit tests
├── .env.example                    # Template for environment variables (PayPal + Gemini)
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
PAYPAL_API_BASE=https://api-m.sandbox.paypal.com
DATABASE_URL=sqlite:///./bountyguard.db
GEMINI_API_KEY=your_gemini_api_key
```

---

### 2. Running Tests

Run the full pytest suite (20 unit, integration, concurrency, and LLM tests):

```bash
pytest
```

---

### 3. Running the Server

Start the local development server:

```bash
uvicorn app.main:app --reload
```

Interactive Swagger UI will be available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

---

## API Workflow Summary

1. **Create Bounty**: `POST /bounties`
2. **Submit PR with Code Diff**: `POST /submissions` (stores immutable `code_diff`)
3. **Execute Automated Tests**: `POST /submissions/{id}/run-tests` (evaluates stored diff; no caller context accepted)
4. **Run Gemini AI Review**: `POST /submissions/{id}/ai-review` (evaluates stored diff against bounty spec with LLM; no caller diff accepted)
5. **Verify Policy Server-Side**: `POST /policy/evaluate` (accepts only `{"submission_id": 1}`)
6. **Initiate Guarded Payout**: `POST /payout/execute` (creates payout with status `PENDING`, bounty `PENDING_PAYOUT`)
7. **Synchronize Payout Status**: `POST /payout/{id}/sync` (transitions to `SUCCESS` and bounty to `PAID` once cleared by PayPal)
8. **PayPal Webhooks**: `POST /webhooks/paypal` (asynchronous status notification)
9. **Inspect Audit Log**: `GET /audit-events`
