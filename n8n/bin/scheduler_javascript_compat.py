"""Bounded ECMAScript string and JSON compatibility primitives."""
from __future__ import annotations

import json
import math
import re


JS_WHITESPACE_CLASS = (
    r"\u0009-\u000d\u0020\u00a0\u1680\u2000-\u200a"
    r"\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def javascript_trim(value: str) -> str:
    """Mirror ECMAScript String.prototype.trim(), not Python str.strip()."""
    return re.sub(
        rf"^[{JS_WHITESPACE_CLASS}]+|[{JS_WHITESPACE_CLASS}]+$",
        "",
        value,
    )


def javascript_json_number(value: int | float) -> str:
    """Render a JSON number with ECMAScript's JSON.stringify thresholds."""
    try:
        number = float(value)
    except OverflowError:
        return "null"
    if not math.isfinite(number):
        return "null"
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    digits, decimal_position = _decimal_digits(abs(number))
    scientific_exponent = decimal_position - 1
    if -6 <= scientific_exponent < 21:
        return sign + _fixed_decimal(digits, decimal_position)
    coefficient = digits if len(digits) == 1 else f"{digits[0]}.{digits[1:]}"
    exponent_sign = "+" if scientific_exponent >= 0 else ""
    return f"{sign}{coefficient}e{exponent_sign}{scientific_exponent}"


def _decimal_digits(number: float) -> tuple[str, int]:
    representation = repr(number).lower()
    if "e" in representation:
        mantissa, raw_exponent = representation.split("e", 1)
        exponent = int(raw_exponent)
    else:
        mantissa = representation
        exponent = 0
    if "." in mantissa:
        integer, fraction = mantissa.split(".", 1)
        digits = integer + fraction
        decimal_position = len(integer) + exponent
    else:
        digits = mantissa
        decimal_position = len(mantissa) + exponent
    leading_zero_count = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0").rstrip("0") or "0"
    decimal_position -= leading_zero_count
    return digits, decimal_position


def _fixed_decimal(digits: str, decimal_position: int) -> str:
    if decimal_position <= 0:
        return f"0.{('0' * -decimal_position)}{digits}"
    if decimal_position >= len(digits):
        return digits + ("0" * (decimal_position - len(digits)))
    return f"{digits[:decimal_position]}.{digits[decimal_position:]}"


def _javascript_number_string(value: int | float) -> str:
    try:
        number = float(value)
    except OverflowError:
        number = math.inf if value > 0 else -math.inf
    if math.isnan(number):
        return "NaN"
    if math.isinf(number):
        return "Infinity" if number > 0 else "-Infinity"
    return javascript_json_number(number)


def javascript_string_value(value: object) -> str:
    """Mirror String(value ?? '') for bounded JSON metadata fields."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _javascript_number_string(value)
    if isinstance(value, list):
        return ",".join(
            javascript_string_value(item) if item is not None else ""
            for item in value
        )
    if isinstance(value, dict):
        return "[object Object]"
    return str(value)


def javascript_safe_string(value: object, max_length: int) -> str:
    """Project safeString() through node-sqlite3's stored-text encoding."""
    collapsed = re.sub(
        rf"[{JS_WHITESPACE_CLASS}]+",
        " ",
        javascript_trim(javascript_string_value(value)),
    )
    encoded = collapsed.encode("utf-16-le", errors="surrogatepass")
    sliced = encoded[: max(0, int(max_length)) * 2].decode(
        "utf-16-le",
        errors="surrogatepass",
    )
    return "".join(
        "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in sliced
    )


def javascript_truthy(value: object) -> bool:
    """Return JavaScript truthiness for JSON-compatible values."""
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            number = math.inf if value > 0 else -math.inf
        if number == 0 or math.isnan(number):
            return False
    if isinstance(value, str) and value == "":
        return False
    return True


def javascript_object_key_order(value: dict[str, object]) -> list[str]:
    """Return JSON.stringify order after canonical Object.fromEntries()."""
    array_indexes: list[tuple[int, str]] = []
    ordinary_keys: list[str] = []
    for key in value:
        if (
            re.fullmatch(r"0|[1-9][0-9]*", key, re.ASCII)
            and int(key) < (2**32 - 1)
        ):
            array_indexes.append((int(key), key))
        else:
            ordinary_keys.append(key)
    array_indexes.sort()
    ordinary_keys.sort(
        key=lambda key: key.encode("utf-16-be", errors="surrogatepass")
    )
    return [key for _, key in array_indexes] + ordinary_keys


def javascript_json_string(value: str) -> str:
    """Use well-formed JSON.stringify escaping while preserving Unicode."""
    encoded = json.dumps(value, ensure_ascii=False)
    return "".join(
        f"\\u{ord(character):04x}"
        if 0xD800 <= ord(character) <= 0xDFFF
        else character
        for character in encoded
    )
