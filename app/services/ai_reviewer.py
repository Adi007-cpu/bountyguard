import json
import logging
import os
import threading
from decimal import Decimal
from typing import Any, Optional
from sqlalchemy.orm import Session

from app.models import (
    AIReviewAssessment,
    AuditEventModel,
    BountyModel,
    ReviewModel,
    ReviewVerdict,
    ReviewerType,
    SubmissionModel,
)

logger = logging.getLogger(__name__)

# Models are tried in this order. Each model has its own free-tier daily quota,
# so a chain gives more free requests and survives a 429 / 404 on one model.
MODEL_CHAIN = [
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
]
CALL_TIMEOUT_SECONDS = 15


def _create_with_timeout(client: Any, model: str, prompt: str, timeout: float) -> Any:
    """Run the Gemini call in a daemon thread so a hang can't block the server."""
    result: dict = {}

    def worker() -> None:
        try:
            result["value"] = client.interactions.create(
                model=model,
                input=prompt,
                response_format={
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": AIReviewAssessment.model_json_schema(),
                },
            )
        except Exception as e:
            result["error"] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"{model} did not respond within {timeout}s")
    if "error" in result:
        raise result["error"]
    return result["value"]


class AIReviewer:
    """Evaluates code submissions using a real Gemini LLM structured review
    and a static security analysis pre-check against bounty specifications.
    Fails closed if the LLM is unavailable or encounters errors.
    """

    SUSPICIOUS_PATTERNS = [
        "os.system(",
        "subprocess.Popen(",
        "subprocess.run(",
        "exec(",
        "eval(",
        "__import__('os')",
        "curl http",
        "wget http",
        "rm -rf",
        "/bin/sh",
        "/bin/bash",
    ]

    def __init__(
        self,
        model: str = "gemini-3.1-flash-lite",
        client: Optional[Any] = None,
        settings: Optional[Any] = None,
    ):
        self.model = model
        self._client = client
        self._settings = settings

    def _get_client(self) -> Optional[Any]:
        if self._client is not None:
            return self._client

        from app.config import get_settings
        settings = self._settings or get_settings()
        api_key = settings.gemini_api_key or os.getenv("GEMINI_API_KEY")
        if not api_key or api_key.strip() in ("", "your_gemini_api_key"):
            return None

        try:
            from google import genai
            self._client = genai.Client(api_key=api_key)
            return self._client
        except Exception as e:
            logger.warning(f"Failed to initialize google-genai Client: {e}")
            return None

    def run_static_security_scan(self, code_diff: str) -> tuple[bool, list[str]]:
        """Fast deterministic rule-based scan for malicious patterns."""
        findings: list[str] = []
        clean = True
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in code_diff:
                clean = False
                findings.append(f"Static security violation: detected '{pattern}' in code diff.")
        return clean, findings

    def evaluate_code(
        self,
        code_diff: str,
        bounty_title: str = "",
        bounty_description: str = "",
    ) -> AIReviewAssessment:
        """Evaluates code diff against bounty specification using real Gemini LLM + static security scanning.
        Fails closed: If LLM is unavailable or encounters an error, never approve.
        """
        # 1. Run static security pre-check
        static_passed, static_findings = self.run_static_security_scan(code_diff)
        if not static_passed:
            return AIReviewAssessment(
                verdict=ReviewVerdict.REJECTED,
                score=0.0,
                summary="Static security scan failed: malicious or dangerous shell/exec patterns detected.",
                security_checks_passed=False,
                spec_requirements_met=False,
                details={"static_findings": static_findings, "llm_skipped": True},
            )

        if not code_diff.strip():
            return AIReviewAssessment(
                verdict=ReviewVerdict.CHANGES_REQUESTED,
                score=0.0,
                summary="Submission contains an empty code diff.",
                security_checks_passed=True,
                spec_requirements_met=False,
                details={"static_findings": ["Empty code diff"]},
            )

        client = self._get_client()

        # 2. FAIL CLOSED: If Gemini client / API key is not configured, do not approve
        if client is None:
            logger.warning("GEMINI_API_KEY is not configured. Failing closed.")
            return AIReviewAssessment(
                verdict=ReviewVerdict.CHANGES_REQUESTED,
                score=0.0,
                summary="AI review unavailable: GEMINI_API_KEY is not configured; automated payout policy denied pending human review.",
                security_checks_passed=False,
                spec_requirements_met=False,
                details={"error": "GEMINI_API_KEY_MISSING", "requires_human_review": True},
            )

        # 3. Call real Gemini LLM with structured output
        prompt = f"""You are BountyGuard's senior security and code review AI.
Evaluate the following pull request code diff against the open-source bounty specification.

--- BOUNTY SPECIFICATION ---
Title: {bounty_title}
Description: {bounty_description}

--- SUBMITTED CODE DIFF ---
{code_diff}

Instructions:
1. Verify if the code changes genuinely address the bounty specification.
2. Check for security vulnerabilities, logic flaws, resource leaks, or backdoor attempts.
3. Determine a verdict ('approved', 'changes_requested', or 'rejected').
4. Assign a score between 0.0 and 1.0.
5. Provide a clear summary and detailed findings.
"""
        try:
            # Try the primary model first, then each model in the chain.
            # A timeout, 429 (quota), 404 (not found) or any other error moves
            # on to the next model instead of hanging.
            models_to_try = [self.model] + [m for m in MODEL_CHAIN if m != self.model]
            interaction = None
            errors: list[str] = []
            for model_name in models_to_try:
                try:
                    interaction = _create_with_timeout(
                        client, model_name, prompt, CALL_TIMEOUT_SECONDS
                    )
                    break
                except Exception as err:
                    logger.warning(f"Model {model_name} failed, trying next: {err}")
                    errors.append(f"{model_name}: {str(err)[:150]}")
            if interaction is None:
                raise RuntimeError("All Gemini models failed. " + " | ".join(errors))

            output_text = interaction.output_text
            if not output_text:
                raise ValueError("Gemini API returned empty output_text.")

            assessment = AIReviewAssessment.model_validate_json(output_text)
            # Enforce static scan safety override
            if not static_passed:
                assessment.security_checks_passed = False
                assessment.verdict = ReviewVerdict.REJECTED
            return assessment

        except Exception as e:
            logger.error(f"Gemini API interaction error during AI review: {e}")
            # FAIL CLOSED on Gemini error/quota/network failure
            return AIReviewAssessment(
                verdict=ReviewVerdict.CHANGES_REQUESTED,
                score=0.0,
                summary=f"AI review could not be completed due to LLM error: {str(e)}; maintainer human review required.",
                security_checks_passed=False,
                spec_requirements_met=False,
                details={"error": str(e), "requires_human_review": True},
            )

    def evaluate_and_record_submission(
        self,
        db: Session,
        submission_id: int,
    ) -> ReviewModel:
        """Loads stored submission and bounty from DB, evaluates with AI, and records ReviewModel and AuditEvent."""
        submission = db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
        if not submission:
            raise ValueError(f"Submission {submission_id} not found.")

        bounty = db.query(BountyModel).filter(BountyModel.id == submission.bounty_id).first()
        if not bounty:
            raise ValueError(f"Associated bounty {submission.bounty_id} not found.")

        # ALWAYS use stored submission code_diff and bounty spec!
        assessment = self.evaluate_code(
            code_diff=submission.code_diff,
            bounty_title=bounty.title,
            bounty_description=bounty.description or "",
        )

        review = ReviewModel(
            submission_id=submission.id,
            reviewer_type=ReviewerType.AI.value,
            verdict=assessment.verdict.value,
            score=Decimal(f"{assessment.score:.2f}"),
            summary=assessment.summary,
            details=json.dumps(assessment.details or {}),
        )
        db.add(review)

        audit = AuditEventModel(
            event_type="AI_REVIEW_COMPLETED",
            submission_id=submission.id,
            bounty_id=submission.bounty_id,
            details=json.dumps(
                {
                    "verdict": assessment.verdict.value,
                    "score": assessment.score,
                    "security_passed": assessment.security_checks_passed,
                    "spec_met": assessment.spec_requirements_met,
                    "summary": assessment.summary,
                }
            ),
        )
        db.add(audit)
        db.commit()
        db.refresh(review)
        return review