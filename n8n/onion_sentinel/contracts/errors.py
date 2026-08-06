"""Normalized errors crossing modular runtime boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ErrorReceipt:
    """Secret-safe error information suitable for callers and audit logs."""

    code: str
    category: str
    retryable: bool
    public_message: str
    exit_code: int = 1
    http_status: int = 500

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "retryable": self.retryable,
            "public_message": self.public_message,
            "exit_code": self.exit_code,
            "http_status": self.http_status,
        }


class BoundaryError(Exception):
    """Keep public failure semantics separate from private diagnostics."""

    def __init__(
        self,
        receipt: ErrorReceipt,
        *,
        diagnostic: str = "",
        context: Mapping[str, Any] | None = None,
    ) -> None:
        if not receipt.code or not receipt.category or not receipt.public_message:
            raise ValueError("boundary errors require code, category, and message")
        super().__init__(receipt.public_message)
        self.receipt = receipt
        self.diagnostic = str(diagnostic or "")
        self.context = dict(context or {})

    def public_dict(self) -> dict[str, Any]:
        """Return only fields approved for user-facing or durable output."""
        return self.receipt.as_dict()
