"""Bounded AC Hunter response normalization and evidence projection."""
from __future__ import annotations

from ac_hunter_config import *  # noqa: F401,F403
from ac_hunter_config import _safe_text  # noqa: F401
from ac_hunter_finding_normalization import (
    FindingNormalizationPrimitives,
    normalize_finding,
)


def _first(mapping: object, names: Sequence[str]) -> object:
    if not isinstance(mapping, dict):
        return None
    for name in names:
        current: object = mapping
        found = True
        for component in name.split("."):
            if not isinstance(current, dict) or component not in current:
                found = False
                break
            current = current[component]
        if found and current not in (None, ""):
            return current
    return None


def _rows(value: object, names: Sequence[str] = ()) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value[:MAX_FINDINGS_PER_MODULE] if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    priority = tuple(names) + (
        "data",
        "results",
        "items",
        "rows",
        "records",
        "findings",
        "hosts",
    )
    for key in priority:
        candidate = value.get(key)
        if isinstance(candidate, list):
            return [
                item
                for item in candidate[:MAX_FINDINGS_PER_MODULE]
                if isinstance(item, dict)
            ]
        if isinstance(candidate, dict):
            nested = _rows(candidate, ())
            if nested:
                return nested
    # Some AC Hunter responses are objects keyed by an address/domain.
    converted: List[Dict[str, Any]] = []
    for key, item in list(value.items())[:MAX_FINDINGS_PER_MODULE]:
        if isinstance(item, dict):
            row = dict(item)
            row.setdefault("host", key)
            converted.append(row)
    return converted


def _number(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        result = float(value)
        return result if result == result and abs(result) != float("inf") else default
    text = str(value or "").strip().replace(",", "")
    try:
        result = float(text)
    except ValueError:
        return default
    return result if result == result and abs(result) != float("inf") else default


def _integer_value(value: object) -> int:
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        candidate = _first(value, ("count", "value", "base", "points", "total"))
        if candidate is value:
            return 0
        return _integer_value(candidate)
    return max(0, int(_number(value, 0)))


def _duration_seconds(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, float(value))
    text = str(value or "").strip()
    if not text:
        return 0.0
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return max(0.0, float(text))
    match = re.fullmatch(
        r"(?:(\d+)\s*d(?:ays?)?\s*)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)",
        text,
        re.IGNORECASE,
    )
    if not match:
        return 0.0
    days, hours, minutes, seconds = match.groups()
    return (
        int(days or 0) * 86400
        + int(hours or 0) * 3600
        + int(minutes or 0) * 60
        + float(seconds)
    )


def _ip(value: object) -> str:
    text = _safe_text(value, 128)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _is_internal(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private


def _string_list(value: object, maximum: int = 20) -> List[str]:
    if isinstance(value, str):
        candidates: Sequence[object] = re.split(r"[,;\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        candidates = list(value)
    else:
        return []
    result: List[str] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = _first(
                candidate,
                ("ip", "address", "host", "fqdn", "domain", "value"),
            )
        text = _safe_text(candidate, 256)
        if text and text not in result:
            result.append(text)
        if len(result) >= maximum:
            break
    return result


def _finding_id(module: str, values: Mapping[str, object]) -> str:
    canonical = json.dumps(
        [module, values.get("source_ip"), values.get("destination_ip"),
         values.get("fqdn"), values.get("port"), values.get("protocol")],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]


_FINDING_NORMALIZATION_PRIMITIVES = FindingNormalizationPrimitives(
    first=_first,
    safe_text=_safe_text,
    ip=_ip,
    is_internal=_is_internal,
    string_list=_string_list,
    number=_number,
    integer_value=_integer_value,
    duration_seconds=_duration_seconds,
    finding_id=_finding_id,
)


def _normalize_finding(module: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    return normalize_finding(module, row, _FINDING_NORMALIZATION_PRIMITIVES)


KNOWN_BENIGN_DOMAINS = (
    ("courier.push.apple.com", "Apple push/courier"),
    ("safebrowsing.apple", "Apple Safe Browsing"),
    ("apple.com", "Apple service"),
    ("icloud.com", "Apple service"),
    ("mzstatic.com", "Apple software distribution"),
    ("apple-dns.net", "Apple service"),
    ("push.services.mozilla.com", "Mozilla push/telemetry"),
    ("telemetry.mozilla.org", "Mozilla push/telemetry"),
    ("services.mozilla.com", "Mozilla service"),
    ("docker.com", "Docker service"),
    ("docker.io", "Docker service"),
    ("raw.githubusercontent.com", "GitHub raw content"),
    ("raw.github.com", "GitHub raw content"),
    ("obsidian.md", "Obsidian release service"),
    ("update.code.visualstudio.com", "Visual Studio Code update service"),
    ("vscode.download.prss.microsoft.com", "Visual Studio Code update service"),
    ("artifacts.elastic.co", "Elastic artifact/update service"),
    ("api.telegram.org", "Telegram API"),
    ("spotify.com", "Spotify service"),
    ("oaistatic.com", "OpenAI static/service infrastructure"),
    ("openai.com", "OpenAI service"),
    ("chatgpt.com", "OpenAI ChatGPT service"),
    ("n8n.io", "n8n service"),
    ("brave.com", "Brave browser service/update"),
)
KNOWN_BENIGN_NETWORKS = (
    (ipaddress.ip_network("17.0.0.0/8"), "Apple service network"),
)
GENERIC_INFRASTRUCTURE_MARKERS = (
    "amazonaws",
    "compute.amazonaws",
    "ec2-",
    "cloudfront",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "azure",
    "cloudapp",
    "googleusercontent",
    "vps",
)
