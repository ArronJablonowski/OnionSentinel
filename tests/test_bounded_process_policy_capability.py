"""Characterization for inherited bounded-process capability validation."""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
import bounded_process_policy as policy  # noqa: E402


TOKEN = "0123456789abcdef" * 4
DESCRIPTOR = 7


def capability_environment(
    *,
    descriptor: object = DESCRIPTOR,
    token: object = TOKEN,
) -> dict[str, str]:
    return {
        policy._CONTAINMENT_FD_ENV: str(descriptor),
        policy._CONTAINMENT_TOKEN_ENV: str(token),
    }


def capability_metadata(
    *,
    mode: int = stat.S_IFREG | 0o600,
    uid: int = 501,
) -> SimpleNamespace:
    return SimpleNamespace(st_mode=mode, st_uid=uid)


class BoundedProcessPolicyCapabilityTests(unittest.TestCase):
    def test_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(policy) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (31, "839813fd79986c933fb041bb71e4a237684e24767aae7e0ab5142f6847005420"),
        )
        self.assertEqual(
            str(inspect.signature(policy._validated_inherited_capability)),
            "() -> 'tuple[int, str] | None'",
        )

    def test_token_must_be_exact_lowercase_hex(self) -> None:
        invalid_tokens = (
            "",
            "0" * 63,
            "0" * 65,
            "g" * 64,
            "A" * 64,
            ("0" * 63) + " ",
        )
        for token in invalid_tokens:
            with self.subTest(token=repr(token)), mock.patch.dict(
                policy.os.environ,
                capability_environment(token=token),
                clear=True,
            ), mock.patch.object(policy.os, "fstat") as fstat:
                self.assertIsNone(policy._validated_inherited_capability())
                fstat.assert_not_called()

    def test_descriptor_must_be_an_integer_at_least_three(self) -> None:
        for descriptor in ("", "not-an-integer", "3.0", "-1", "0", "1", "2"):
            with self.subTest(descriptor=descriptor), mock.patch.dict(
                policy.os.environ,
                capability_environment(descriptor=descriptor),
                clear=True,
            ), mock.patch.object(policy.os, "fstat") as fstat:
                self.assertIsNone(policy._validated_inherited_capability())
                fstat.assert_not_called()

    def test_valid_owner_only_regular_capability_returns_descriptor_and_token(
        self,
    ) -> None:
        expected = policy._CONTAINMENT_PREFIX + TOKEN.encode("ascii")
        with mock.patch.dict(
            policy.os.environ,
            capability_environment(),
            clear=True,
        ), mock.patch.object(
            policy.os,
            "fstat",
            return_value=capability_metadata(),
        ) as fstat, mock.patch.object(
            policy.os,
            "pread",
            return_value=expected,
        ) as pread, mock.patch.object(
            policy.os,
            "getuid",
            return_value=501,
        ) as getuid:
            self.assertEqual(
                policy._validated_inherited_capability(),
                (DESCRIPTOR, TOKEN),
            )

        fstat.assert_called_once_with(DESCRIPTOR)
        pread.assert_called_once_with(DESCRIPTOR, len(expected) + 1, 0)
        getuid.assert_called_once_with()

    def test_metadata_and_payload_must_prove_the_exact_capability(self) -> None:
        expected = policy._CONTAINMENT_PREFIX + TOKEN.encode("ascii")
        cases = (
            ("not regular", capability_metadata(mode=stat.S_IFDIR | 0o600), expected),
            ("wrong owner", capability_metadata(uid=502), expected),
            ("group readable", capability_metadata(mode=stat.S_IFREG | 0o640), expected),
            ("world writable", capability_metadata(mode=stat.S_IFREG | 0o602), expected),
            ("truncated payload", capability_metadata(), expected[:-1]),
            ("trailing payload", capability_metadata(), expected + b"x"),
        )
        for name, metadata, payload in cases:
            with self.subTest(name=name), mock.patch.dict(
                policy.os.environ,
                capability_environment(),
                clear=True,
            ), mock.patch.object(
                policy.os,
                "fstat",
                return_value=metadata,
            ), mock.patch.object(
                policy.os,
                "pread",
                return_value=payload,
            ), mock.patch.object(
                policy.os,
                "getuid",
                return_value=501,
            ):
                self.assertIsNone(policy._validated_inherited_capability())

    def test_descriptor_probe_errors_fail_closed(self) -> None:
        for function, error in (("fstat", OSError("closed")), ("pread", ValueError("bad read"))):
            with self.subTest(function=function), mock.patch.dict(
                policy.os.environ,
                capability_environment(),
                clear=True,
            ), mock.patch.object(
                policy.os,
                "fstat",
                return_value=capability_metadata(),
            ), mock.patch.object(
                policy.os,
                "pread",
                return_value=policy._CONTAINMENT_PREFIX + TOKEN.encode("ascii"),
            ), mock.patch.object(policy.os, function, side_effect=error):
                self.assertIsNone(policy._validated_inherited_capability())


if __name__ == "__main__":
    unittest.main()
