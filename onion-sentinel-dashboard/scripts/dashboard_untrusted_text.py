"""Bounded Unicode admission for untrusted dashboard presentation values."""
from __future__ import annotations

from typing import Optional


REPLACEMENT = "\N{REPLACEMENT CHARACTER}"
SAFE_CONTROL_CHARACTERS = frozenset({"\t", "\n", "\r"})
BIDI_CONTROL_CODEPOINTS = frozenset({
    0x061C, 0x200E, 0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
})


def normalize_untrusted_text(
    value: object,
    *,
    max_characters: Optional[int] = None,
) -> str:
    """Return bounded, UTF-8-encodable text without unsafe controls.

    Evidence remains data: this function does not interpret, decode, or execute
    its contents. Invalid surrogate code points, terminal controls, and bidi
    instruction controls become visible replacement characters.
    """
    raw = str(value or "")
    limit = max(1, int(max_characters)) if max_characters is not None else None
    truncated = limit is not None and len(raw) > limit
    if truncated:
        raw = raw[:max(0, limit - 1)]
    normalized = "".join(
        character
        if _admitted_character(character)
        else REPLACEMENT
        for character in raw
    )
    return normalized + ("…" if truncated else "")


def _admitted_character(character: str) -> bool:
    codepoint = ord(character)
    if 0xD800 <= codepoint <= 0xDFFF:
        return False
    if codepoint in BIDI_CONTROL_CODEPOINTS:
        return False
    if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
        return character in SAFE_CONTROL_CHARACTERS
    return True
