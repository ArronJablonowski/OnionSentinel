"""Typed state and transition ledger for the AI analysis composition root."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class Stage(str, Enum):
    CREATED = "created"
    LOAD = "load"
    ATTEST = "attest"
    PREPARE = "prepare"
    PRIMARY_ANALYSIS = "primary_analysis"
    GOVERNED_PIVOTS = "governed_pivots"
    INDEPENDENT_REVIEW = "independent_review"
    ADJUDICATION = "adjudication"
    DETERMINISTIC_GUARDS = "deterministic_guards"
    VALIDATE = "validate"
    COMMIT = "commit"
    POST_COMMIT = "post_commit"
    COMPLETE = "complete"
    FAILED = "failed"


ORDER = (
    Stage.CREATED,
    Stage.LOAD,
    Stage.ATTEST,
    Stage.PREPARE,
    Stage.PRIMARY_ANALYSIS,
    Stage.GOVERNED_PIVOTS,
    Stage.INDEPENDENT_REVIEW,
    Stage.ADJUDICATION,
    Stage.DETERMINISTIC_GUARDS,
    Stage.VALIDATE,
    Stage.COMMIT,
    Stage.POST_COMMIT,
    Stage.COMPLETE,
)


def _bounded_text(value: object, label: str, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ValueError(f"{label} is invalid")
    return text


@dataclass(frozen=True)
class Transition:
    sequence: int
    previous: Stage
    current: Stage
    reason: str


@dataclass(frozen=True)
class RuntimePathDefaults:
    log_dir: Path
    index_queue_dir: Path
    index_quarantine_dir: Path
    memory_receipt_dir: Path
    memory_pending_dir: Path
    memory_committed_dir: Path


@dataclass(frozen=True)
class RuntimePaths:
    log_dir: Path
    log_file: Path
    current_file: Path
    active_dir: Path
    index_queue_dir: Path
    index_quarantine_dir: Path
    memory_receipt_dir: Path
    memory_pending_dir: Path
    memory_committed_dir: Path

    @classmethod
    def resolve(
        cls,
        runtime_dir: Path | None,
        defaults: RuntimePathDefaults,
    ) -> "RuntimePaths":
        if runtime_dir is None:
            log_dir = Path(defaults.log_dir)
            return cls(
                log_dir=log_dir,
                log_file=log_dir / "llm-analysis-log.jsonl",
                current_file=log_dir / "current-analysis.json",
                active_dir=log_dir / "active",
                index_queue_dir=Path(defaults.index_queue_dir),
                index_quarantine_dir=Path(defaults.index_quarantine_dir),
                memory_receipt_dir=Path(defaults.memory_receipt_dir),
                memory_pending_dir=Path(defaults.memory_pending_dir),
                memory_committed_dir=Path(defaults.memory_committed_dir),
            )
        root = Path(runtime_dir)
        log_dir = root / "llm-analysis-logs"
        return cls(
            log_dir=log_dir,
            log_file=log_dir / "llm-analysis-log.jsonl",
            current_file=log_dir / "current-analysis.json",
            active_dir=log_dir / "active",
            index_queue_dir=root / "analysis-index-pending",
            index_quarantine_dir=root / "analysis-index-quarantine",
            memory_receipt_dir=root / "memory-writeback-receipts",
            memory_pending_dir=root / "memory-writeback-pending",
            memory_committed_dir=root / "memory-writeback-committed",
        )


@dataclass
class RuntimeContext:
    run_id: str
    arguments: Any
    controlled_evaluation: bool = False
    runtime_dir: Path | None = None
    paths: RuntimePaths | None = None
    prompt_path: Path | None = None
    prompt_package: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None
    artifacts: tuple[Path, ...] = ()
    stage: Stage = Stage.CREATED
    transitions: list[Transition] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.run_id = _bounded_text(self.run_id, "run id", 128)
        if self.runtime_dir is not None:
            self.runtime_dir = Path(self.runtime_dir)
        if self.prompt_path is not None:
            self.prompt_path = Path(self.prompt_path)
        self.prompt_package = dict(self.prompt_package)
        self.settings = dict(self.settings)
        if self.response is not None:
            self.response = dict(self.response)
        self.artifacts = tuple(Path(item) for item in self.artifacts)

    def advance(self, stage: Stage, reason: str) -> Transition:
        if self.stage in {Stage.COMPLETE, Stage.FAILED}:
            raise ValueError("terminal pipeline state cannot advance")
        expected = ORDER[ORDER.index(self.stage) + 1]
        if stage is not expected:
            raise ValueError(
                f"invalid pipeline transition: {self.stage.value} -> {stage.value}"
            )
        transition = Transition(
            sequence=len(self.transitions) + 1,
            previous=self.stage,
            current=stage,
            reason=_bounded_text(reason, "transition reason", 256),
        )
        self.stage = stage
        self.transitions.append(transition)
        return transition

    def fail(self, reason: str) -> Transition:
        if self.stage in {Stage.COMPLETE, Stage.FAILED}:
            raise ValueError("terminal pipeline state cannot fail again")
        transition = Transition(
            sequence=len(self.transitions) + 1,
            previous=self.stage,
            current=Stage.FAILED,
            reason=_bounded_text(reason, "failure reason", 256),
        )
        self.stage = Stage.FAILED
        self.transitions.append(transition)
        return transition

    def audit(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            {
                "sequence": item.sequence,
                "previous": item.previous.value,
                "current": item.current.value,
                "reason": item.reason,
            }
            for item in self.transitions
        )
