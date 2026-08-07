"""Pure JSON request-body parsing for report portal HTTP handlers."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import TypeVar


T = TypeVar('T')


@dataclass(frozen=True)
class ParsedJsonBody:
    """Preserve the distinction between malformed JSON and valid JSON null."""

    valid: bool
    value: object | None

    @property
    def is_object(self) -> bool:
        return self.valid and isinstance(self.value, dict)

    def value_or(self, fallback: T) -> object | T | None:
        return self.value if self.valid else fallback


def parse_json_body(raw: str, *, empty_object: bool = False) -> ParsedJsonBody:
    """Parse one decoded request body without applying endpoint policy.

    ``empty_object`` preserves the legacy ``json.loads(raw or "{}")`` mode.
    Malformed JSON is represented by ``valid=False``; valid JSON ``null`` is
    represented by ``valid=True`` and ``value=None``.
    """
    source = (raw or '{}') if empty_object else raw
    try:
        return ParsedJsonBody(valid=True, value=json.loads(source))
    except json.JSONDecodeError:
        return ParsedJsonBody(valid=False, value=None)
