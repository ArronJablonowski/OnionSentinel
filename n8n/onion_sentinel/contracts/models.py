"""Small validated data objects used at new package seams."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


def _required_text(value: object, label: str, maximum: int = 1024) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label} is invalid")
    return text


@dataclass(frozen=True)
class ModelRoute:
    provider: str
    model: str
    reasoning_effort: str = "medium"

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _required_text(self.provider, "provider", 64))
        object.__setattr__(self, "model", _required_text(self.model, "model", 256))
        effort = _required_text(self.reasoning_effort, "reasoning effort", 32).lower()
        if effort not in {"low", "medium", "high", "xhigh"}:
            raise ValueError("reasoning effort is unsupported")
        object.__setattr__(self, "reasoning_effort", effort)

    @property
    def canonical(self) -> str:
        return f"{self.provider}:{self.model}:{self.reasoning_effort}"


@dataclass(frozen=True)
class ProviderRequest:
    route: ModelRoute
    role: str
    payload: Mapping[str, Any]
    prompt_bytes: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _required_text(self.role, "role", 64))
        if self.prompt_bytes < 0:
            raise ValueError("prompt bytes cannot be negative")
        if self.timeout_seconds <= 0:
            raise ValueError("provider timeout must be positive")
        object.__setattr__(self, "payload", dict(self.payload))


@dataclass(frozen=True)
class ProviderReceipt:
    route: ModelRoute
    response: Mapping[str, Any]
    observed_model: str
    observed_provider: str
    runtime_seconds: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "observed_model",
            _required_text(self.observed_model, "observed model", 256),
        )
        object.__setattr__(
            self,
            "observed_provider",
            _required_text(self.observed_provider, "observed provider", 64),
        )
        if self.runtime_seconds < 0:
            raise ValueError("provider runtime cannot be negative")
        object.__setattr__(self, "response", dict(self.response))


@dataclass(frozen=True)
class QueryRequest:
    query_id: str
    backend: str
    operation: str
    parameters: Mapping[str, Any]
    authorization_ref: str

    def __post_init__(self) -> None:
        for name in ("query_id", "backend", "operation", "authorization_ref"):
            object.__setattr__(self, name, _required_text(getattr(self, name), name))
        object.__setattr__(self, "parameters", dict(self.parameters))


@dataclass(frozen=True)
class QueryReceipt:
    request: QueryRequest
    status: str
    read_only: bool
    evidence: Mapping[str, Any]
    gaps: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", _required_text(self.status, "status", 64))
        if not self.read_only:
            raise ValueError("investigation query receipts must attest read-only execution")
        object.__setattr__(self, "evidence", dict(self.evidence))
        object.__setattr__(self, "gaps", tuple(str(item) for item in self.gaps))


@dataclass(frozen=True)
class ReviewReceipt:
    disposition: str
    confidence: str
    material_disagreement: bool
    reasons: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "disposition", _required_text(self.disposition, "disposition"))
        object.__setattr__(self, "confidence", _required_text(self.confidence, "confidence", 32))
        object.__setattr__(self, "reasons", tuple(str(item) for item in self.reasons))


@dataclass(frozen=True)
class ConclusionReceipt:
    verdict: str
    confidence: str
    evidence_references: Sequence[str]
    automation_allowed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", _required_text(self.verdict, "verdict"))
        object.__setattr__(self, "confidence", _required_text(self.confidence, "confidence", 32))
        references = tuple(_required_text(item, "evidence reference") for item in self.evidence_references)
        object.__setattr__(self, "evidence_references", references)


@dataclass(frozen=True)
class CommitReceipt:
    commit_id: str
    artifacts: Sequence[str]
    post_commit_tasks: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "commit_id", _required_text(self.commit_id, "commit id"))
        object.__setattr__(self, "artifacts", tuple(str(item) for item in self.artifacts))
        object.__setattr__(
            self,
            "post_commit_tasks",
            tuple(str(item) for item in self.post_commit_tasks),
        )
