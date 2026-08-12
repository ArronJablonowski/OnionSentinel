"""Exact compatibility facade for the owner-managed CTI program workspace."""
from __future__ import annotations

from cti_program_contract import *  # noqa: F403
from cti_program_validation import *  # noqa: F403
from cti_program_store import *  # noqa: F403

# Keep required compatibility symbols visible to static release-contract checks
# while preserving the exact objects and runtime namespace imported above.
CTIProgramError = CTIProgramError  # type: ignore[name-defined]  # noqa: F405
CTIProgramConflict = CTIProgramConflict  # type: ignore[name-defined]  # noqa: F405
normalize_program = normalize_program  # type: ignore[name-defined]  # noqa: F405
load_program = load_program  # type: ignore[name-defined]  # noqa: F405
save_program = save_program  # type: ignore[name-defined]  # noqa: F405
program_digest = program_digest  # type: ignore[name-defined]  # noqa: F405
public_response = public_response  # type: ignore[name-defined]  # noqa: F405
