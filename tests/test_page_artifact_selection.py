"""Regressions for bounded filename selection without losing group evidence."""
from pathlib import Path
from types import SimpleNamespace
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "onion-sentinel-dashboard"))
from portal_soc_record_runtime import soc_alert_page_ai_artifact_context


class PageArtifactSelectionTests(unittest.TestCase):
    def test_legacy_and_group_member_artifacts_are_selected(self):
        paths = [Path(name) for name in (
            "20261011-120000-0600-newest-local-ai-analysis.json",
            "20261011-110000-0600-earlier-local-ai-analysis.json",
            "20261010-110000-0600-unrelated-local-ai-analysis.json",
            "legacy-local-ai-analysis.json",
        )]
        base = SimpleNamespace(
            prompt_paths=lambda: paths, analysis_paths=lambda: paths,
            read_record=lambda _: {}, modified_time=lambda _: 1,
        )
        selected = {}

        def build(sources, **kwargs):
            selected["analyses"] = list(sources.analysis_paths())
            selected["prompts"] = list(sources.prompt_paths())
            return {}

        runtime = SimpleNamespace(
            re=re, page_group_keys=lambda _: ["group"],
            _soc_ai_group_members=lambda _: [("group", "index:earlier")],
            _soc_ai_artifact_sources=lambda: base,
            AiArtifactSources=lambda **kwargs: SimpleNamespace(**kwargs),
            AiArtifactContextDependencies=lambda **kwargs: kwargs,
            soc_alert_group_id=lambda key: key,
            build_ai_artifact_index=build,
            compose_page_ai_artifact_context=lambda *args: args[1],
        )
        soc_alert_page_ai_artifact_context(runtime, [{"alert_id": "index:newest"}])
        for values in selected.values():
            self.assertEqual(values, [paths[0], paths[1], paths[3]])


if __name__ == "__main__":
    unittest.main()
