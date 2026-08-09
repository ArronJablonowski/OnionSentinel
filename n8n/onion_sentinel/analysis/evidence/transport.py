"""Model evidence copying and hosted fixed-point synchronization."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    internal_keys: frozenset[str]
    hosted_forbidden_keys: frozenset[str]
    list_path_sentinel: object
    fixed_point_max_passes: int


@dataclass(frozen=True)
class Dependencies:
    redact_asset_owners: Callable[[Any], Any]
    reviewed_sha256_path: Callable[[tuple[object, ...]], bool]
    exact_columnar_envelope: Callable[..., bool]
    sanitize_hosted_evidence: Callable[..., Any]
    refinalize_columnar_envelope: Callable[[Any], Any]
    evidence_reference_contract: Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class SynchronizationDependencies:
    model_safe_copy: Callable[[dict[str, Any]], dict[str, Any]]
    prompt_json_bytes: Callable[[Any], bytes]
    validation_error: Callable[[str], Exception]


class _Copier:
    def __init__(self, policy: Policy, dependencies: Dependencies) -> None:
        self.policy = policy
        self.dependencies = dependencies

    def copy(
        self, value: Any, *, hosted: bool, reviewer_safe: bool,
        path: tuple[object, ...],
    ) -> Any:
        if isinstance(value, dict):
            return self._mapping(value, hosted, reviewer_safe, path)
        if isinstance(value, list):
            return [
                self.copy(
                    item, hosted=hosted, reviewer_safe=reviewer_safe,
                    path=(*path, self.policy.list_path_sentinel),
                )
                for item in value
            ]
        return value

    def _mapping(
        self, value: dict[Any, Any], hosted: bool, reviewer_safe: bool,
        path: tuple[object, ...],
    ) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for raw_key, raw_item in value.items():
            key, item_path = str(raw_key), (*path, str(raw_key))
            admitted, item = self._admit_item(key, raw_item, item_path, hosted)
            if admitted:
                output[key] = self.copy(
                    item, hosted=hosted, reviewer_safe=reviewer_safe, path=item_path,
                )
        self._redact_owners(output, hosted, reviewer_safe)
        self._finalize_root(output, hosted, path)
        return output

    def _admit_item(
        self, key: str, item: Any, path: tuple[object, ...], hosted: bool,
    ) -> tuple[bool, Any]:
        reviewed_hash = self._reviewed_hash(key, path, hosted)
        if self._skip_key(key, hosted, reviewed_hash):
            return False, item
        if reviewed_hash and (not isinstance(item, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", item)):
            return False, item
        if hosted and key in {"investigation_query_results", "live_osquery_evidence"}:
            item = self._project_hosted(item, path)
        return True, item

    def _reviewed_hash(
        self, key: str, path: tuple[object, ...], hosted: bool,
    ) -> bool:
        return (
            key == "sha256" and hosted
            and self.dependencies.reviewed_sha256_path(path[:-1])
        )

    def _skip_key(self, key: str, hosted: bool, reviewed_hash: bool) -> bool:
        if key.startswith("_local_"):
            return True
        if key in self.policy.internal_keys and not reviewed_hash:
            return True
        return hosted and (
            key in self.policy.hosted_forbidden_keys
            or key.startswith("_pcap_query_")
        )

    def _project_hosted(self, item: Any, path: tuple[object, ...]) -> Any:
        preserve = path == ("investigation_query_results",) and (
            self.dependencies.exact_columnar_envelope(
                item, require_encoded_accounting=True,
            )
        )
        return self.dependencies.sanitize_hosted_evidence(
            item, path, preserve_columnar_rows=preserve,
        )

    def _redact_owners(
        self, output: dict[str, Any], hosted: bool, reviewer_safe: bool,
    ) -> None:
        if (hosted or reviewer_safe) and "asset_context" in output:
            output["asset_context"] = self.dependencies.redact_asset_owners(
                output["asset_context"]
            )

    def _finalize_root(
        self, output: dict[str, Any], hosted: bool, path: tuple[object, ...],
    ) -> None:
        if not hosted or path or "investigation_query_results" not in output:
            return
        output["investigation_query_results"] = self.dependencies.refinalize_columnar_envelope(
            output["investigation_query_results"]
        )
        output["evidence_reference_contract"] = self.dependencies.evidence_reference_contract(output)


def model_safe_copy(
    value: Any, *, hosted: bool, reviewer_safe: bool,
    path: tuple[object, ...], policy: Policy, dependencies: Dependencies,
) -> Any:
    """Copy model evidence while enforcing route disclosure controls."""
    return _Copier(policy, dependencies).copy(
        value, hosted=hosted, reviewer_safe=reviewer_safe, path=path,
    )


def synchronize_hosted_contract(
    prompt_package: dict[str, Any], *, maximum_passes: int,
    dependencies: SynchronizationDependencies,
) -> dict[str, Any]:
    """Transactionally bind a package to its hosted transport fixed point."""
    working = copy.deepcopy(prompt_package)
    seen: set[str] = set()
    for _ in range(maximum_passes):
        transported = dependencies.model_safe_copy(working)
        encoded = dependencies.prompt_json_bytes(transported)
        digest = hashlib.sha256(encoded).hexdigest()
        if digest in seen:
            raise dependencies.validation_error(
                "hosted investigation transport did not reach a fixed point (projection cycle)"
            )
        seen.add(digest)
        candidate = _replace_transport_fields(working, transported)
        verified = dependencies.model_safe_copy(candidate)
        if dependencies.prompt_json_bytes(verified) == encoded:
            _commit_transport_fields(prompt_package, candidate)
            return prompt_package
        working = candidate
    raise dependencies.validation_error(
        "hosted investigation transport did not reach a fixed point"
    )


def _replace_transport_fields(
    working: dict[str, Any], transported: dict[str, Any],
) -> dict[str, Any]:
    candidate = copy.deepcopy(working)
    for key in ("investigation_query_results", "evidence_reference_contract"):
        if key in transported:
            candidate[key] = transported[key]
        else:
            candidate.pop(key, None)
    return candidate


def _commit_transport_fields(
    prompt_package: dict[str, Any], candidate: dict[str, Any],
) -> None:
    for key in ("investigation_query_results", "evidence_reference_contract"):
        prompt_package.pop(key, None)
        if key in candidate:
            prompt_package[key] = candidate[key]
