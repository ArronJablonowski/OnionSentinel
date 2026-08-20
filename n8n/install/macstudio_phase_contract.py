"""Validate the ordered, side-effect-sensitive Mac Studio install phases."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import tempfile
from typing import NamedTuple, Sequence


SCHEMA = "onion-sentinel-macstudio-phase-contract-v1"
PHASE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


class PhaseContractError(RuntimeError):
    """The phase graph or its binding to the installer is invalid."""


class Phase(NamedTuple):
    phase_id: str
    after: tuple[str, ...]
    marker: str
    source_offset: int


def _phase_records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {"schema", "phases"}:
        raise PhaseContractError("phase contract has invalid root fields")
    if value.get("schema") != SCHEMA:
        raise PhaseContractError("phase contract schema is unsupported")
    phases = value.get("phases")
    if not isinstance(phases, list) or not phases:
        raise PhaseContractError("phase contract must contain phases")
    if not all(isinstance(item, dict) for item in phases):
        raise PhaseContractError("each phase must be an object")
    return phases


def _phase_id(record: dict[str, object], seen: set[str]) -> str:
    value = record.get("id")
    if not isinstance(value, str) or not PHASE_ID_RE.fullmatch(value):
        raise PhaseContractError("phase identifier is unsafe")
    if value in seen:
        raise PhaseContractError("duplicate phase identifier")
    return value


def _phase_dependencies(record: dict[str, object]) -> tuple[str, ...]:
    value = record.get("after")
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise PhaseContractError("phase dependencies are invalid")
    if len(value) != len(set(value)):
        raise PhaseContractError("phase dependencies are invalid")
    return tuple(value)


def _phase_marker(record: dict[str, object], installer: str) -> str:
    value = record.get("marker")
    if not isinstance(value, str) or not value or len(value) > 512:
        raise PhaseContractError("phase marker is invalid")
    if installer.count(value) != 1:
        raise PhaseContractError("phase marker must occur exactly once")
    return value


def _parse_phases(value: object, installer: str) -> tuple[Phase, ...]:
    parsed: list[Phase] = []
    seen: set[str] = set()
    for record in _phase_records(value):
        if set(record) != {"id", "after", "marker"}:
            raise PhaseContractError("phase has invalid fields")
        phase_id = _phase_id(record, seen)
        marker = _phase_marker(record, installer)
        parsed.append(
            Phase(
                phase_id,
                _phase_dependencies(record),
                marker,
                installer.index(marker),
            )
        )
        seen.add(phase_id)
    return tuple(parsed)


def _validate_graph(phases: tuple[Phase, ...]) -> None:
    by_id = {phase.phase_id: phase for phase in phases}
    for phase in phases:
        unknown = set(phase.after) - set(by_id)
        if unknown:
            raise PhaseContractError("phase has an unknown dependency")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(phase_id: str) -> None:
        if phase_id in visiting:
            raise PhaseContractError("phase dependency cycle detected")
        if phase_id in visited:
            return
        visiting.add(phase_id)
        for dependency in by_id[phase_id].after:
            visit(dependency)
        visiting.remove(phase_id)
        visited.add(phase_id)

    for phase in phases:
        visit(phase.phase_id)


def validate_phase_contract(value: object, installer: str) -> tuple[Phase, ...]:
    phases = _parse_phases(value, installer)
    _validate_graph(phases)
    offsets = [phase.source_offset for phase in phases]
    if offsets != sorted(offsets):
        raise PhaseContractError("phase list does not match installer source order")
    by_id = {phase.phase_id: phase for phase in phases}
    for phase in phases:
        if any(by_id[item].source_offset >= phase.source_offset for item in phase.after):
            raise PhaseContractError("phase dependency violates installer source order")
    return phases


def load_and_validate(contract_path: Path, installer_path: Path) -> tuple[Phase, ...]:
    try:
        value = json.loads(contract_path.read_text(encoding="utf-8"))
        installer = installer_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PhaseContractError("phase contract inputs are unavailable") from exc
    return validate_phase_contract(value, installer)


def _write_report(path: Path, phases: tuple[Phase, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ok": True, "schema": SCHEMA, "phase_count": len(phases)}
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        phases = load_and_validate(args.contract, args.installer)
    except PhaseContractError as exc:
        print(str(exc))
        return 2
    if args.report is not None:
        _write_report(args.report, phases)
    print(f"Mac Studio installer phase contract passed: {len(phases)} phases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
