from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query.audit import (
    IncidentAttestationDependencies,
    attach_incident_attestation,
)


class IncidentQueryAttestationTests(unittest.TestCase):
    def dependencies(
        self,
        *,
        queries: list | None = None,
        osquery: list | None = None,
    ) -> IncidentAttestationDependencies:
        return IncidentAttestationDependencies(
            query_audit=lambda _package: {"queries": queries if queries is not None else [{}]},
            osquery_audit=lambda _package: {"queries": osquery if osquery is not None else [{}]},
            live_osquery_audit=lambda _package: {"queries": [{"host": "endpoint"}]},
        )

    def test_soc_role_is_unchanged(self) -> None:
        response = {"summary": "soc"}
        self.assertIs(
            attach_incident_attestation(
                response, {}, agent_role="soc-analyst",
                dependencies=self.dependencies(queries=[]),
            ),
            response,
        )
        self.assertNotIn("_incident_query_audit", response)

    def test_incident_role_attaches_only_collector_owned_audits(self) -> None:
        response = {"_incident_query_audit": {"queries": ["model-forgery"]}}
        attach_incident_attestation(
            response,
            {"incident_response_evidence": {"schema": "onion-sentinel-incident-evidence-v2"}},
            agent_role="incident-responder",
            dependencies=self.dependencies(),
        )
        self.assertEqual(response["_incident_query_audit"], {"queries": [{}]})
        self.assertEqual(response["_incident_live_osquery_audit"]["queries"][0]["host"], "endpoint")

    def test_incident_role_rejects_missing_query_audit(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no validated queries"):
            attach_incident_attestation(
                {}, {}, agent_role="incident-responder",
                dependencies=self.dependencies(queries=[]),
            )

    def test_v2_evidence_requires_validated_osquery_commands(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no validated commands"):
            attach_incident_attestation(
                {},
                {"incident_response_evidence": {"schema": "onion-sentinel-incident-evidence-v2"}},
                agent_role="incident-responder",
                dependencies=self.dependencies(osquery=[]),
            )


if __name__ == "__main__":
    unittest.main()
