from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    pending = "pending"
    leased = "leased"
    done = "done"
    dead = "dead"


class Job(BaseModel):
    id: UUID
    type: str
    payload: dict[str, Any]
    idempotency_key: str
    status: JobStatus
    attempts: int
    leased_by: str | None
    leased_until: datetime | None
    run_after: datetime
    created_at: datetime
    updated_at: datetime
    lease_recovered_at: datetime | None = None
    # NOT a DB column — only claim_batch()'s query computes and aliases
    # this via EXTRACT(EPOCH FROM ...); every other query leaves it at
    # its default of None. See queue.py's claim_batch() docstring.
    lease_recovery_seconds: float | None = None

    @classmethod
    def from_record(cls, record: dict) -> "Job":
        return cls(**record)


class DeadLetter(BaseModel):
    id: UUID
    type: str
    payload: dict[str, Any]
    idempotency_key: str
    attempts: int
    failed_reason: str | None
    moved_at: datetime
    created_at: datetime

    @classmethod
    def from_record(cls, record: dict) -> "DeadLetter":
        return cls(**record)


class ReapResult(BaseModel):
    """Return shape for reap_expired_leases() — deliberately carries the
    full dead-lettered payloads (not just a count), so a caller that
    cares about GitHub (posting a "couldn't review" comment) can act on
    them without a second query. This module itself stays GitHub-agnostic;
    it just hands back structured data.
    """
    dead_lettered: list[DeadLetter] = Field(default_factory=list)
    requeued_count: int = 0

    @property
    def total(self) -> int:
        return len(self.dead_lettered) + self.requeued_count
