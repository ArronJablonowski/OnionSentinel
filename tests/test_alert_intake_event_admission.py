import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('event_intake', ROOT / 'n8n/bin/onion-sentinel-alert-intake.py')
intake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intake)

class AdmissionTests(unittest.TestCase):
    def test_old_invalid_and_raw_original_are_terminal_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / 'policy.json'
            policy.write_text(json.dumps({'enabled': True, 'time_zone': 'America/Denver',
                                          'min_event_date': '2026-10-08'}))
            with mock.patch.object(intake, 'POLICY_FILE', policy), mock.patch.object(
                    intake, 'PAUSE_FILE', Path(directory)/'pause'), mock.patch.object(intake.request, 'urlopen') as network:
                for payload in [{}, {'timestamp': '2026-08-26  18:45:20.050-06:00'},
                                {'timestamp': '2099-01-01T00:00:00Z', 'security_onion': {
                                    'raw_event': {'@timestamp': '2026-08-26T00:00:00Z'}}}]:
                    result = intake.post_message('id', payload)
                    self.assertTrue(result['ok'])
                    self.assertFalse(result['retryable'])
                    self.assertEqual(result['status'], 'dropped')
                network.assert_not_called()
                self.assertIsNone(intake.event_admission({'timestamp': '2099-01-01T00:00:00Z'}))
