"""Bounded text traversal and repetition checks for independent reviews."""

from __future__ import annotations

import collections
import re
from typing import Any


def response_strings(value: Any) -> list[str]:
    """Return normalized public strings from a nested model response."""
    output: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).startswith("_"):
                continue
            output.extend(response_strings(child))
    elif isinstance(value, list):
        for child in value:
            output.extend(response_strings(child))
    elif isinstance(value, str):
        text = re.sub(r"\s+", " ", value).strip()
        if text:
            output.append(text)
    return output


def repetition_reasons(response: dict[str, Any]) -> list[str]:
    """Detect repeated unrelated boilerplate without policing ordinary prose."""
    strings = response_strings(response)
    normalized = [
        re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
        for text in strings
        if len(text) >= 80
    ]
    counts = collections.Counter(normalized)
    reasons: list[str] = []
    if any(count >= 3 for count in counts.values()):
        reasons.append("the same long passage was repeated across three or more fields")
    for text in normalized:
        words = text.split()
        if len(words) < 40:
            continue
        grams = [" ".join(words[index:index + 6]) for index in range(len(words) - 5)]
        if grams and (len(grams) - len(set(grams))) / len(grams) > 0.35:
            reasons.append("one response field contains excessive repeated six-word sequences")
            break
    return reasons
