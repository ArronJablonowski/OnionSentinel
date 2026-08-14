#!/usr/bin/env python3
"""Compatibility facade for bounded, role-aware Onion Sentinel agent memory.

The implementation is split by ownership: validation and schema policy,
bounded journal I/O and retrieval, and deterministic promotion/quarantine.
This module preserves the historical import surface for scripts and tests.
"""
from __future__ import annotations

import sys
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from agent_memory_journal import (  # noqa: E402,F401
    MANAGED_END,
    MANAGED_START,
    MEMORY_SNAPSHOT_SCHEMA,
    RECORD_RE,
    _atomic_write_text,
    _bounded_utf8,
    _load_text_locked,
    _record_is_expired,
    _record_markdown,
    _records_from_managed,
    _relevance_score,
    _split_managed,
    build_agent_execution_context,
    build_agent_memory_context,
    initialize_memory_file,
    load_memory_context,
    read_memory_file,
)
from agent_memory_promotion import (  # noqa: E402,F401
    _empty_persist_stats,
    _is_poisoned_bpfdoor_code_zero_record,
    _merge_record,
    _ordered_records,
    _write_records,
    persist_memory_candidates,
    quarantine_bpfdoor_code_zero_memory,
)
from agent_memory_context_contract import (  # noqa: E402,F401
    MEMORY_CONTEXT_CONTRACT_SCHEMA,
    SUMMARY_REQUIREMENTS,
    WORKING_MEMORY_SECTIONS,
    attach_agent_memory_context_contract,
    build_agent_memory_context_contract,
    rebind_agent_memory_context_contract,
    refresh_selected_memory_snapshot,
)
from agent_memory_validation import (  # noqa: E402,F401
    ACTIVE_MEMORY_STATUSES,
    AGENT_MEMORY_FILES,
    AGENT_PROMPT_FILES,
    AGENT_SECOND_OPINION_PROMPT_FILES,
    CONFIDENCE_RANK,
    DEFAULT_ROLE_RECORD_LIMIT,
    DEFAULT_SHARED_RECORD_LIMIT,
    MEMORY_CATEGORIES,
    MEMORY_ROLES,
    SECRET_PATTERNS,
    STOP_WORDS,
    TOKEN_RE,
    _candidate_id,
    _clean_text,
    _contains_secret,
    _new_record,
    _parse_time,
    _tokens,
    normalize_memory_candidate,
    normalize_memory_candidates,
    project_now,
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)


__all__ = [
    "ACTIVE_MEMORY_STATUSES",
    "AGENT_MEMORY_FILES",
    "AGENT_PROMPT_FILES",
    "AGENT_SECOND_OPINION_PROMPT_FILES",
    "CONFIDENCE_RANK",
    "DEFAULT_ROLE_RECORD_LIMIT",
    "DEFAULT_SHARED_RECORD_LIMIT",
    "MANAGED_END",
    "MANAGED_START",
    "MEMORY_CONTEXT_CONTRACT_SCHEMA",
    "MEMORY_SNAPSHOT_SCHEMA",
    "MEMORY_CATEGORIES",
    "MEMORY_ROLES",
    "RECORD_RE",
    "SECRET_PATTERNS",
    "STOP_WORDS",
    "TOKEN_RE",
    "SUMMARY_REQUIREMENTS",
    "WORKING_MEMORY_SECTIONS",
    "attach_agent_memory_context_contract",
    "build_agent_memory_context_contract",
    "rebind_agent_memory_context_contract",
    "refresh_selected_memory_snapshot",
    "build_agent_execution_context",
    "build_agent_memory_context",
    "initialize_memory_file",
    "load_memory_context",
    "normalize_memory_candidate",
    "normalize_memory_candidates",
    "persist_memory_candidates",
    "project_now",
    "quarantine_bpfdoor_code_zero_memory",
    "read_memory_file",
    "role_memory_file",
    "role_prompt_file",
    "role_second_opinion_prompt_file",
]
