from datetime import datetime
from decimal import Decimal
from enum import Enum
import json
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.database import Base


# --- Database Enums / Statuses ---

class BountyStatus(str, Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    PENDING_PAYOUT = "pending_payout"
    PAID = "paid"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class SubmissionStatus(str, Enum):
    PENDING = "pending"
    EVALUATING = "evaluating"
    APPROVED = "approved"
    REJECTED = "rejected"
    PAID = "paid"


class ReviewerType(str, Enum):
    AI = "ai"
    MAINTAINER = "maintainer"


class ReviewVerdict(str, Enum):
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    REJECTED = "rejected"


class PayoutStatus(str, Enum):
    INITIATED = "initiated"
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RECONCILED = "reconciled"


# --- SQLAlchemy Models ---

class BountyModel(Base):
    __tablename__ = "bounties"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(3), default="USD", nullable=False)
    status = Column(String(50), default=BountyStatus.OPEN.value, nullable=False, index=True)
    test_suite_spec = Column(Text, nullable=True)  # Server-owned maintainer acceptance test spec (JSON)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    submissions = relationship("SubmissionModel", back_populates="bounty", cascade="all, delete-orphan")
    payout = relationship("PayoutModel", back_populates="bounty", uselist=False)


class SubmissionModel(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True, index=True)
    bounty_id = Column(Integer, ForeignKey("bounties.id"), nullable=False, index=True)
    contributor_email = Column(String(255), nullable=False)
    pr_url = Column(String(500), nullable=False)
    code_diff = Column(Text, nullable=False)  # Frozen immutable code diff from PR or pre-seeded fixture
    commit_sha = Column(String(100), nullable=True)  # Git commit SHA
    diff_source = Column(String(50), default="preseeded_fixture", nullable=False)  # "github_pr_diff" or "preseeded_fixture"
    status = Column(String(50), default=SubmissionStatus.PENDING.value, nullable=False, index=True)
    ci_passed = Column(Boolean, default=False, nullable=False)
    maintainer_approved = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    bounty = relationship("BountyModel", back_populates="submissions")
    reviews = relationship("ReviewModel", back_populates="submission", cascade="all, delete-orphan")
    payouts = relationship("PayoutModel", back_populates="submission")


class ReviewModel(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False, index=True)
    reviewer_type = Column(String(50), nullable=False)  # "ai" or "maintainer"
    verdict = Column(String(50), nullable=False)  # "approved", "rejected", "changes_requested"
    score = Column(Numeric(4, 2), nullable=True)  # Confidence or quality score (0.0 - 1.0)
    summary = Column(Text, nullable=False)
    details = Column(Text, nullable=True)  # JSON-encoded details
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    submission = relationship("SubmissionModel", back_populates="reviews")


class PayoutModel(Base):
    __tablename__ = "payouts"
    __table_args__ = (
        UniqueConstraint("bounty_id", name="uq_payout_bounty_id"),  # Strictly one payout per bounty
    )

    id = Column(Integer, primary_key=True, index=True)
    bounty_id = Column(Integer, ForeignKey("bounties.id"), nullable=False, unique=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False, index=True)
    sender_batch_id = Column(String(100), nullable=False, unique=True, index=True)  # Persisted UUID
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(3), default="USD", nullable=False)
    recipient_email = Column(String(255), nullable=False)
    status = Column(String(50), default=PayoutStatus.INITIATED.value, nullable=False, index=True)
    paypal_batch_id = Column(String(255), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    bounty = relationship("BountyModel", back_populates="payout")
    submission = relationship("SubmissionModel", back_populates="payouts")


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    bounty_id = Column(Integer, nullable=True, index=True)
    submission_id = Column(Integer, nullable=True, index=True)
    payout_id = Column(Integer, nullable=True, index=True)
    details = Column(Text, nullable=True)  # JSON representation of event context
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# --- Pydantic Schemas ---

class AcceptanceCriteria(BaseModel):
    required_symbols: list[str] = Field(default_factory=list, description="Function or class names required in the submission")
    forbidden_symbols: list[str] = Field(default_factory=list, description="Disallowed patterns or functions")
    min_score: float = Field(default=0.85, ge=0.0, le=1.0, description="Minimum AI review score required")


class BountyCreate(BaseModel):
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    amount: Decimal = Field(..., gt=Decimal("0.00"), decimal_places=2)
    currency: str = Field(default="USD", max_length=3)
    acceptance_criteria: Optional[AcceptanceCriteria] = None
    test_suite_spec: Optional[str] = None

    @model_validator(mode="after")
    def populate_test_suite_spec(self) -> "BountyCreate":
        if self.acceptance_criteria and not self.test_suite_spec:
            self.test_suite_spec = json.dumps(self.acceptance_criteria.model_dump())
        return self


class BountyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    amount: Decimal
    currency: str
    status: str
    test_suite_spec: Optional[str] = None
    created_at: datetime


class SubmissionCreate(BaseModel):
    bounty_id: int
    contributor_email: str
    pr_url: str
    code_diff: Optional[str] = Field(
        default=None,
        description="Frozen code diff from the submitted pull request or pre-seeded verified fixture",
    )
    commit_sha: Optional[str] = Field(default=None, description="Git commit SHA from the pull request")


class SubmissionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    bounty_id: int
    contributor_email: str
    pr_url: str
    code_diff: str
    commit_sha: Optional[str] = None
    diff_source: str
    status: str
    ci_passed: bool
    maintainer_approved: bool
    created_at: datetime


class MaintainerApprovalRequest(BaseModel):
    approved: bool = Field(default=True, description="Whether maintainer approves the submission for payout")
    notes: Optional[str] = Field(default=None, description="Maintainer review feedback or sign-off notes")


class AIReviewAssessment(BaseModel):
    """Structured assessment produced by LLM and static analysis."""
    verdict: ReviewVerdict = Field(description="Review decision: approved, changes_requested, or rejected")
    score: float = Field(..., ge=0.0, le=1.0, description="Quality/confidence score from 0.0 to 1.0")
    summary: str = Field(..., description="High-level summary of the code review findings")
    security_checks_passed: bool = Field(description="True if no malicious or dangerous code was detected")
    spec_requirements_met: bool = Field(description="True if the submitted diff fulfills the bounty specification")
    details: Optional[dict[str, Any]] = Field(default=None, description="Detailed breakdown of findings")


class ReviewRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    submission_id: int
    reviewer_type: str
    verdict: str
    score: Optional[Decimal] = None
    summary: str
    created_at: datetime


class PolicyEvaluationRequest(BaseModel):
    submission_id: int


class PolicyEvaluationResult(BaseModel):
    allowed: bool
    submission_id: int
    bounty_id: Optional[int] = None
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    recipient_email: Optional[str] = None
    reasons: list[str] = []


class PayoutExecuteRequest(BaseModel):
    submission_id: int


class PayoutSyncResponse(BaseModel):
    payout_id: int
    status: str
    paypal_batch_id: Optional[str] = None
    bounty_status: str
    message: str


class PayoutRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    bounty_id: int
    submission_id: int
    sender_batch_id: str
    amount: Decimal
    currency: str
    recipient_email: str
    status: str
    paypal_batch_id: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
