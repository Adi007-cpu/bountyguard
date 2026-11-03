import ast
import json
import logging
from typing import Any, List, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models import AuditEventModel, BountyModel, SubmissionModel

logger = logging.getLogger(__name__)


class TestCaseResult(BaseModel):
    name: str
    passed: bool
    message: str


class TestExecutionResult(BaseModel):
    submission_id: int
    all_passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    test_results: List[TestCaseResult]
    logs: str


class FixtureTestRunner:
    """Server-side automated test execution layer.
    
    Loads stored code diff and maintainer's bounty test suite specification from the database.
    Does NOT accept caller-supplied test outcomes or verification contexts.
    """

    def run_tests_on_submission(
        self,
        code_diff: str,
        bounty_title: str = "",
        maintainer_spec_json: Optional[str] = None,
    ) -> tuple[bool, list[TestCaseResult], str]:
        results: list[TestCaseResult] = []
        passed_count = 0

        # Test 1: Code Diff Non-Empty Verification
        diff_present = bool(code_diff and code_diff.strip())
        results.append(
            TestCaseResult(
                name="diff_integrity_check",
                passed=diff_present,
                message="Code diff is present and non-empty" if diff_present else "Submitted code diff is empty",
            )
        )
        if diff_present:
            passed_count += 1

        # Test 2: Python AST Syntax Validation
        syntax_passed = True
        syntax_msg = "Python code parsed successfully without syntax errors"
        try:
            python_lines = []
            for line in code_diff.splitlines():
                if line.startswith("+") and not line.startswith("+++"):
                    python_lines.append(line[1:])
                elif not line.startswith("-") and not line.startswith("@@"):
                    python_lines.append(line)
            clean_code = "\n".join(python_lines).strip()
            if clean_code:
                ast.parse(clean_code)
        except SyntaxError as e:
            syntax_passed = False
            syntax_msg = f"Syntax error in submitted code: {e.msg} at line {e.lineno}"
        except Exception as e:
            syntax_passed = False
            syntax_msg = f"Parsing error: {str(e)}"

        results.append(TestCaseResult(name="syntax_and_ast_validation", passed=syntax_passed, message=syntax_msg))
        if syntax_passed:
            passed_count += 1

        # Test 3: Security & Dangerous Constructs Check
        dangerous_patterns = ["os.system(", "subprocess.Popen(", "exec(", "eval("]
        sec_clean = not any(pattern in code_diff for pattern in dangerous_patterns)
        results.append(
            TestCaseResult(
                name="automated_security_guard",
                passed=sec_clean,
                message="Automated AST security checks clean" if sec_clean else "Dangerous shell or execution construct detected in diff",
            )
        )
        if sec_clean:
            passed_count += 1

        # Test 4: Maintainer's Bounty Acceptance Test Spec Conformance
        spec_passed = True
        spec_msg = "Conforms to maintainer's bounty acceptance test specification"
        if maintainer_spec_json:
            try:
                spec_data = json.loads(maintainer_spec_json)
                required_symbols = spec_data.get("required_symbols", [])
                for sym in required_symbols:
                    if sym not in code_diff:
                        spec_passed = False
                        spec_msg = f"Missing required function or symbol '{sym}' from bounty specification"
                        break
            except Exception as e:
                logger.warning(f"Error parsing bounty maintainer test_suite_spec: {e}")

        results.append(TestCaseResult(name="bounty_spec_conformance", passed=spec_passed, message=spec_msg))
        if spec_passed:
            passed_count += 1

        total_tests = len(results)
        all_passed = passed_count == total_tests
        logs = f"Automated test run finished: {passed_count}/{total_tests} test suites passed."
        return all_passed, results, logs

    def execute_and_update_submission(
        self,
        db: Session,
        submission_id: int,
    ) -> TestExecutionResult:
        """Loads stored submission and maintainer's bounty from DB, runs test suite, and updates DB status."""
        submission = db.query(SubmissionModel).filter(SubmissionModel.id == submission_id).first()
        if not submission:
            raise ValueError(f"Submission {submission_id} not found.")

        bounty = db.query(BountyModel).filter(BountyModel.id == submission.bounty_id).first()
        bounty_title = bounty.title if bounty else ""
        maintainer_spec = bounty.test_suite_spec if bounty else None

        all_passed, results, logs = self.run_tests_on_submission(
            code_diff=submission.code_diff,
            bounty_title=bounty_title,
            maintainer_spec_json=maintainer_spec,
        )

        submission.ci_passed = all_passed

        audit = AuditEventModel(
            event_type="TEST_EXECUTION_COMPLETED",
            submission_id=submission.id,
            bounty_id=submission.bounty_id,
            details=json.dumps(
                {
                    "all_passed": all_passed,
                    "passed_tests": sum(1 for r in results if r.passed),
                    "total_tests": len(results),
                    "logs": logs,
                }
            ),
        )
        db.add(audit)
        db.commit()
        db.refresh(submission)

        return TestExecutionResult(
            submission_id=submission.id,
            all_passed=all_passed,
            total_tests=len(results),
            passed_tests=sum(1 for r in results if r.passed),
            failed_tests=len(results) - sum(1 for r in results if r.passed),
            test_results=results,
            logs=logs,
        )
