"""Resource Library filesystem, metadata, and mutation policy.

The HTTP compatibility runtime owns configuration.  This module owns the
bounded path lookup and deterministic mutation behavior without importing the
portal handler or host-specific defaults.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path


ResourceSources = Sequence[tuple[str, Path]]


def resource_library_id_for(path: Path) -> str:
    return hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12]


def _exact_source_pdf(
    resource_id: str,
    source_path: str,
    sources: ResourceSources,
) -> tuple[Path, str, Path] | None:
    if not source_path:
        return None
    try:
        candidate = Path(source_path).expanduser().resolve()
    except Exception:
        return None
    if (
        candidate.suffix.lower() != ".pdf"
        or not candidate.name
        or candidate.name.startswith("._")
    ):
        return None
    for category, root in sources:
        try:
            rel = candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if resource_library_id_for(candidate) == resource_id and candidate.is_file():
            return candidate, category, rel
    return None


def _recursive_source_pdf(
    resource_id: str,
    sources: ResourceSources,
) -> tuple[Path, str, Path] | None:
    for category, root in sources:
        if not root.exists():
            continue
        for src in root.rglob("*.pdf"):
            if (
                any(part == "__MACOSX" for part in src.parts)
                or src.name.startswith("._")
                or not src.is_file()
            ):
                continue
            rel = src.relative_to(root)
            if category == "CheatSheets" and rel.parts and rel.parts[0] == "SANS_Posters":
                continue
            if resource_library_id_for(src) == resource_id:
                return src, category, rel
    return None


def find_resource_library_pdf(
    resource_id: str,
    source_path: str,
    sources: ResourceSources,
) -> tuple[Path, str, Path] | None:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return None
    return _exact_source_pdf(resource_id, source_path, sources) or _recursive_source_pdf(
        resource_id, sources
    )


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(1, 1000):
        candidate = path.with_name(f"{stem} ({index}){suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not find unique removal destination for {path.name}")


def load_resource_library_metadata(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_resource_library_metadata(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def clean_resource_tags(values: object) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if isinstance(values, str):
        values = re.split(r"[,;\n]+", values)
    if not isinstance(values, list):
        return []
    for value in values:
        tag = re.sub(r"\s+", " ", str(value)).strip()[:40]
        if not tag:
            continue
        key = tag.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
    return out[:12]


def sanitize_resource_filename(name: str, original_suffix: str) -> str:
    suffix = original_suffix if original_suffix.startswith(".") else f".{original_suffix}"
    suffix = suffix or ".pdf"
    cleaned = re.sub(r"[/:\\]+", "-", name).strip().strip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)[:120].strip()
    if not cleaned:
        raise ValueError("New filename is empty")
    if Path(cleaned).suffix:
        cleaned = cleaned[: -len(Path(cleaned).suffix)].rstrip(" .")
    if not cleaned:
        raise ValueError("New filename is empty")
    cleaned = f"{cleaned}{suffix}"
    if cleaned.startswith("._") or cleaned in {".", ".."}:
        raise ValueError("Invalid filename")
    return cleaned


def resource_favorites(data: dict) -> list[str]:
    favorites = data.get("_favorites", [])
    if not isinstance(favorites, list):
        return []
    return sorted({str(item) for item in favorites if re.fullmatch(r"[a-f0-9]{12}", str(item))})


def set_resource_favorite(
    resource_id: str,
    favorite: bool,
    *,
    load_metadata: Callable[[], dict],
    save_metadata: Callable[[dict], None],
    queue_action: Callable[[dict], dict],
    trigger_worker: Callable[[], None],
) -> tuple[bool, dict]:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return False, {"ok": False, "error": "Invalid resource id"}
    data = load_metadata()
    favorites = set(resource_favorites(data))
    (favorites.add if favorite else favorites.discard)(resource_id)
    data["_favorites"] = sorted(favorites)
    save_metadata(data)
    queue_action({"action": "refresh", "reason": "favorite", "id": resource_id})
    trigger_worker()
    return True, {"ok": True, "favorite": favorite, "favorites": sorted(favorites)}


def set_resource_tags(
    resource_id: str,
    tags: object,
    *,
    load_metadata: Callable[[], dict],
    save_metadata: Callable[[dict], None],
    queue_action: Callable[[dict], dict],
    trigger_worker: Callable[[], None],
) -> tuple[bool, dict]:
    if not re.fullmatch(r"[a-f0-9]{12}", resource_id or ""):
        return False, {"ok": False, "error": "Invalid resource id"}
    cleaned = clean_resource_tags(tags)
    data = load_metadata()
    entry = data.get(resource_id, {}) if isinstance(data.get(resource_id, {}), dict) else {}
    entry["custom_tags"] = cleaned
    data[resource_id] = entry
    save_metadata(data)
    queue_action({"action": "refresh", "reason": "tags", "id": resource_id})
    trigger_worker()
    return True, {"ok": True, "tags": cleaned, "queued": True}


def rename_resource_file(
    resource_id: str,
    source_path: str,
    new_name: str,
    *,
    find_pdf: Callable[[str, str], tuple[Path, str, Path] | None],
    load_metadata: Callable[[], dict],
    save_metadata: Callable[[dict], None],
    queue_action: Callable[[dict], dict],
    trigger_worker: Callable[[], None],
    refresh_library: Callable[[], None],
) -> tuple[bool, dict]:
    found = find_pdf(resource_id, source_path)
    if not found:
        return False, {"ok": False, "error": "Resource not found"}
    src, _category, _rel = found
    try:
        safe_name = sanitize_resource_filename(new_name, src.suffix)
    except ValueError as exc:
        return False, {"ok": False, "error": str(exc)}
    dest = src.with_name(safe_name)
    if dest.resolve() == src.resolve():
        return False, {"ok": False, "error": f"Rename aborted: the file is already named '{dest.name}'. No files were changed."}
    if dest.exists():
        return False, {"ok": False, "error": f"Rename aborted: a file named '{dest.name}' already exists. No files were changed."}
    display_title = re.sub(r"[_-]+", " ", dest.stem).strip() or dest.stem
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        result = queue_action({"action": "rename", "id": resource_id, "source": str(src), "new_name": safe_name, "portal_error": str(exc)})
        trigger_worker()
        result.update({"display_title": display_title, "source": str(src), "target_source": str(dest), "refresh_after_ms": 65000})
        return True, result
    except Exception as exc:
        return False, {"ok": False, "error": f"Rename failed: {exc}"}
    data = load_metadata()
    old_entry = data.pop(resource_id, None)
    new_id = resource_library_id_for(dest)
    if isinstance(old_entry, dict):
        data[new_id] = old_entry
    favorites = data.get("_favorites", [])
    if isinstance(favorites, list) and resource_id in favorites:
        data["_favorites"] = sorted({new_id if item == resource_id else str(item) for item in favorites})
    save_metadata(data)
    try:
        refresh_library()
    except Exception as exc:
        return True, {"ok": True, "warning": f"Renamed file on disk, but Resource Library refresh failed: {exc}", "new_id": new_id, "source": str(dest), "display_title": display_title, "renamed_on_disk": True}
    return True, {"ok": True, "new_id": new_id, "source": str(dest), "display_title": display_title, "renamed_on_disk": True, "refresh_after_ms": 1200}


def move_resource_to_removal(
    resource_id: str,
    source_path: str,
    *,
    removal_dir: Path,
    find_pdf: Callable[[str, str], tuple[Path, str, Path] | None],
    queue_removal: Callable[[str, str, str], dict],
    refresh_library: Callable[[], None],
) -> tuple[bool, dict]:
    found = find_pdf(resource_id, source_path)
    if not found:
        return False, {"ok": False, "error": "Resource not found"}
    src, category, rel = found
    dest = unique_destination(removal_dir / category / rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(src), str(dest))
    except PermissionError as exc:
        return True, queue_removal(resource_id, str(src), str(exc))
    except Exception as exc:
        return False, {"ok": False, "error": f"Move failed: {exc}"}
    try:
        refresh_library()
    except Exception as exc:
        return True, {"ok": True, "warning": f"Moved file, but Resource Library refresh failed: {exc}", "moved_to": str(dest), "title": src.name}
    return True, {"ok": True, "moved_to": str(dest), "title": src.name}
