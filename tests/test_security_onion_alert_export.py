"""Static safety checks for burst-aware Security Onion alert export."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SecurityOnionAlertExportTest(unittest.TestCase):
    def test_export_uses_stable_search_after_pagination(self) -> None:
        code = (ROOT / "security-onion" / "bin" / "export-recent-alerts").read_text()
        self.assertIn('SEARCH_AFTER_FIELD=', code)
        self.assertIn('"search_after": $SEARCH_AFTER', code.replace('\\"', '"'))
        self.assertIn(".hits.hits[-1].sort // empty", code)
        self.assertIn('"_shard_doc"', code)
        self.assertNotIn('{"_id": {"order": "desc"}}', code)
        self.assertIn("preference=onion-sentinel-alert-export", code)
        self.assertIn('SO_ALERT_MAX_TOTAL', code)
        self.assertIn('saturated: $saturated', code)

    def test_export_caps_server_side_work(self) -> None:
        code = (ROOT / "security-onion" / "bin" / "export-recent-alerts").read_text()
        self.assertIn('MAX_SIZE=500', code)
        self.assertIn('MAX_TOTAL > 20000', code)

    def test_export_rejects_partial_shard_failure(self) -> None:
        wrapper = ROOT / "security-onion" / "bin" / "export-recent-alerts"
        response = {
            "took": 1,
            "timed_out": False,
            "_shards": {
                "total": 2,
                "successful": 1,
                "failed": 1,
                "failures": [
                    {
                        "index": ".synthetic-alert-index",
                        "reason": {
                            "type": "illegal_argument_exception",
                            "reason": "synthetic shard failure",
                        },
                    }
                ],
            },
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            query_bin = Path(temp_dir) / "query"
            query_bin.write_text(
                "#!/bin/sh\ncat <<'JSON'\n"
                + json.dumps(response)
                + "\nJSON\n",
                encoding="utf-8",
            )
            query_bin.chmod(0o755)
            env = os.environ.copy()
            env["SO_ELASTICSEARCH_QUERY_BIN"] = str(query_bin)
            result = subprocess.run(
                [str(wrapper)],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("returned failed shards", result.stderr)


if __name__ == "__main__":
    unittest.main()
