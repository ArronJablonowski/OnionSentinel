"""Dependency-inversion ports for incremental runtime extraction."""
from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from .models import (
    CommitReceipt,
    ConclusionReceipt,
    ProviderReceipt,
    ProviderRequest,
    QueryReceipt,
    QueryRequest,
    ReviewReceipt,
)


class ProviderAdapter(Protocol):
    def invoke(self, request: ProviderRequest) -> ProviderReceipt:
        ...


class QueryEngine(Protocol):
    def execute(self, requests: Sequence[QueryRequest]) -> Sequence[QueryReceipt]:
        ...


class EvidenceProjector(Protocol):
    def project(self, evidence: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


class ReviewPipeline(Protocol):
    def review(
        self,
        primary_result: Mapping[str, Any],
        evidence_package: Mapping[str, Any],
    ) -> ReviewReceipt:
        ...


class AdjudicationPipeline(Protocol):
    def adjudicate(
        self,
        primary_result: Mapping[str, Any],
        review: ReviewReceipt,
        evidence_package: Mapping[str, Any],
    ) -> ReviewReceipt:
        ...


class ConclusionPipeline(Protocol):
    def conclude(self, analysis_state: Mapping[str, Any]) -> ConclusionReceipt:
        ...


class ResultUnitOfWork(Protocol):
    def commit(
        self,
        terminal_result: Mapping[str, Any],
        artifact_plan: Mapping[str, Any],
    ) -> CommitReceipt:
        ...


class MemoryRepository(Protocol):
    def stage(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        ...

    def promote(self, commit_receipt: CommitReceipt) -> Mapping[str, Any]:
        ...


class ReportRenderer(Protocol):
    def render(self, terminal_result: Mapping[str, Any]) -> str:
        ...


class JobRepository(Protocol):
    def claim(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        ...

    def transition(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


class HarnessRepository(Protocol):
    def append(self, operation: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


class PortalService(Protocol):
    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


class AlertStoreService(Protocol):
    def execute(self, command: Mapping[str, Any]) -> Mapping[str, Any]:
        ...
