#!/usr/bin/env python3
"""Prove cryptographic and atomic lifecycle controls for v2 skills."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import investigation_skill_lifecycle_v2 as lifecycle  # noqa: E402
import investigation_skill_registry_v2 as registry  # noqa: E402
import investigation_skill_signing_v2 as signing  # noqa: E402
import investigation_skills_v2 as skills  # noqa: E402


CANDIDATE = (
    ROOT
    / "n8n/config/investigation-skills-v2-candidates/dns-triage-v2.candidate.json"
)


def promoted_manifest(identifier: str) -> dict[str, object]:
    value = json.loads(CANDIDATE.read_text(encoding="utf-8"))
    value["id"] = identifier
    value["maintainer"]["reviewer"] = "independent-reviewer"
    value["verification"] = {
        "unit_tests": True,
        "replay_cases": 5,
        "independent_query_review": True,
        "adversarial_tests": True,
        "human_approved": True,
    }
    value["artifact_digest"] = skills.artifact_digest(value)
    return value


def raw_snapshot(
    manifest: dict[str, object], *, revision: int, previous: str = "",
) -> dict[str, object]:
    return {
        "schema": registry.SCHEMA,
        "revision": revision,
        "mode": "active",
        "provider_scope": registry.PROVIDER_SCOPE,
        "previous_registry_digest": previous,
        "revoked_artifact_digests": [],
        "records": [{
            "state": "active",
            "manifest": manifest,
            "dependencies": [],
            "conflicts": [],
        }],
    }


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class InvestigationSkillLifecycleV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = self.root / "operator-private.pem"
        self.public_key = self.root / "operator-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "pkey", "-in", str(self.private_key),
                "-pubout", "-out", str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )
        self.private_key.chmod(0o600)
        self.public_key.chmod(0o600)
        self.signer = signing.openssl_ed25519_signer(
            self.private_key,
            key_id="operator-release-key",
        )
        self.verifier = signing.openssl_ed25519_verifier(
            {"operator-release-key": self.public_key}
        )
        self.registry_root = self.root / "registry"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def snapshot(
        self, identifier: str, *, revision: int, previous: str = "",
    ) -> dict[str, object]:
        return registry.seal_registry(
            raw_snapshot(
                promoted_manifest(identifier),
                revision=revision,
                previous=previous,
            ),
            signer=self.signer,
        )

    def test_real_ed25519_signature_binds_payload_and_trust_key(self) -> None:
        value = self.snapshot("network.dns.primary", revision=1)

        self.assertEqual(
            registry.validate_registry(value, verifier=self.verifier),
            value,
        )
        tampered = dict(value)
        tampered["registry_digest"] = registry.registry_digest(tampered)
        tampered["revision"] = 2
        tampered["registry_digest"] = registry.registry_digest(tampered)
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            registry.validate_registry(tampered, verifier=self.verifier)

    def test_atomic_activation_compare_and_swap_and_exact_rollback(self) -> None:
        previous = self.snapshot("network.dns.previous", revision=1)
        current = self.snapshot(
            "network.dns.current",
            revision=2,
            previous=previous["registry_digest"],
        )

        first = lifecycle.activate_snapshot(
            self.registry_root,
            previous,
            expected_current_digest="",
            verifier=self.verifier,
        )
        second = lifecycle.activate_snapshot(
            self.registry_root,
            current,
            expected_current_digest=previous["registry_digest"],
            verifier=self.verifier,
        )

        self.assertEqual(first["action"], "activate")
        self.assertEqual(second["previous_registry_digest"], previous["registry_digest"])
        self.assertEqual(
            lifecycle.load_current(self.registry_root, verifier=self.verifier),
            current,
        )
        self.assertEqual(
            os.stat(self.registry_root).st_mode & 0o777,
            0o700,
        )
        self.assertEqual(
            os.stat(self.registry_root / "current.json").st_mode & 0o777,
            0o600,
        )

        with self.assertRaisesRegex(ValueError, "current registry changed"):
            lifecycle.activate_snapshot(
                self.registry_root,
                previous,
                expected_current_digest=previous["registry_digest"],
                verifier=self.verifier,
            )
        self.assertEqual(
            lifecycle.load_current(self.registry_root, verifier=self.verifier),
            current,
        )

        receipt = lifecycle.rollback_active(
            self.registry_root,
            expected_current_digest=current["registry_digest"],
            verifier=self.verifier,
        )
        self.assertEqual(receipt["action"], "rollback")
        self.assertEqual(receipt["registry_digest"], previous["registry_digest"])
        self.assertEqual(
            lifecycle.load_current(self.registry_root, verifier=self.verifier),
            previous,
        )

    def test_symlinked_registry_root_fails_before_write(self) -> None:
        target = self.root / "target"
        target.mkdir(mode=0o700)
        self.registry_root.symlink_to(target, target_is_directory=True)
        value = self.snapshot("network.dns.primary", revision=1)

        with self.assertRaisesRegex(ValueError, "symlink"):
            lifecycle.activate_snapshot(
                self.registry_root,
                value,
                expected_current_digest="",
                verifier=self.verifier,
            )
        self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
