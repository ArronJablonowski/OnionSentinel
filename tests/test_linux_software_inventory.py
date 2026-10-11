"""Fixture-only end-to-end Linux package contracts; no live queries."""
import datetime as dt
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'n8n/bin'), str(ROOT/'relay/app'), str(ROOT/'onion-sentinel-dashboard')]
import software_inventory_workflow as workflow
import software_inventory_validation as validation
import software_inventory_transport as transport
import software_inventory_normalization as normalization
import software_inventory_state as dashboard
import software_inventory_response_projection as projection
import incident_evidence_software as broker

loader = importlib.machinery.SourceFileLoader('linux_export_test', str(ROOT/'security-onion/bin/export-software-observations'))
spec = importlib.util.spec_from_loader(loader.name, loader)
exporter = importlib.util.module_from_spec(spec)
loader.exec_module(exporter)

WINDOW = {'start': '2026-10-01T00:00:00.000Z', 'end': '2026-10-08T00:00:00.000Z'}

def bucket(name='accountsservice', arch='amd64', release=None):
    return {'key': {'asset': 'appletv', 'product': name, 'version': '22.07.5',
                    'architecture': arch, 'release': release}, 'doc_count': 3,
            'first_seen': {'value_as_string': '2026-10-07T09:00:00Z'},
            'last_seen': {'value_as_string': '2026-10-07T10:00:00Z'},
            'latest': {'hits': {'hits': [{'_source': {'host': {'os': {'name': 'Ubuntu', 'type': 'linux', 'version': '22.04.5'}}}}]}}}

class LinuxSoftwareInventoryTests(unittest.TestCase):
    def response(self, source='osquery_deb', buckets=None, page_size=500, after=None):
        request = transport.build_request(source, WINDOW, page_size, after)
        raw = {'timed_out': False, '_shards': {'total': 1, 'successful': 1, 'failed': 0},
               'aggregations': {'software': {'buckets': buckets or []}}}
        result = subprocess.CompletedProcess([], 0, json.dumps(raw).encode(), b'')
        with mock.patch.object(exporter, 'run_bounded_command', return_value=result):
            response = exporter.execute_request(request)
        broker.validate_software_request(request)
        broker.validate_software_response(response, request)
        return validation.validate_relay_response(response, expected_source=source, expected_window=WINDOW,
            requested_page_size=page_size, previous_after=after, build_request=transport.build_request)

    def test_export_broker_import_and_dashboard_preserve_linux_package_and_os(self):
        response = self.response(buckets=[bucket()])
        record = response['records'][0]
        self.assertEqual(record['platform'], 'linux')
        self.assertEqual(record['tier'], 'installed')
        self.assertEqual(record['package_manager'], 'deb')
        self.assertEqual(record['architecture'], 'amd64')
        self.assertEqual(record['operating_system_type'], 'Ubuntu')
        self.assertEqual(record['operating_system_version'], '22.04.5')
        self.assertEqual(dashboard._sanitize_record(record)['package_manager'], 'deb')

    def test_identity_includes_architecture_and_rpm_release_and_repeats_are_stable(self):
        base, _ = exporter.normalize_bucket('osquery_rpm', bucket(release='1.el9'))
        again, _ = exporter.normalize_bucket('osquery_rpm', bucket(release='1.el9'))
        arm, _ = exporter.normalize_bucket('osquery_rpm', bucket(arch='aarch64', release='1.el9'))
        update, _ = exporter.normalize_bucket('osquery_rpm', bucket(release='2.el9'))
        self.assertEqual(base['evidence_id'], again['evidence_id'])
        self.assertEqual(len({base['evidence_id'], arm['evidence_id'], update['evidence_id']}), 3)
        self.assertEqual(base['package_release'], '1.el9')
        self.assertEqual(normalization._normalize_record(base)['package_release'], '1.el9')

    def test_fixed_query_uses_scheduled_discriminator_and_five_part_cursor(self):
        query = exporter.build_query('osquery_deb', exporter.parse_timestamp(WINDOW['start']),
            exporter.parse_timestamp(WINDOW['end']), 500, None)
        self.assertIn({'term': {'action_id': 'pack_onionsentinel-software-inventory_linux_deb'}}, query['query']['bool']['filter'])
        self.assertIn({'term': {'host.os.type': 'linux'}}, query['query']['bool']['filter'])
        self.assertEqual([next(iter(x)) for x in query['aggs']['software']['composite']['sources']],
                         ['asset', 'product', 'version', 'architecture', 'release'])

    def test_more_than_500_records_bind_and_advance_cursor_without_duplicates(self):
        rows = [bucket(name=f'package-{index:04}') for index in range(1001)]
        first = self.response(buckets=rows[:501])
        self.assertIsNone(first['after']['release'])
        self.assertFalse(first['complete'])
        self.assertEqual(len(first['records']), 500)
        second = self.response(buckets=rows[500:], after=first['after'])
        third = self.response(buckets=rows[1000:], after=second['after'])
        self.assertTrue(third['complete'])
        identities = [r['evidence_id'] for page in (first,second,third) for r in page['records']]
        self.assertEqual(len(set(identities)), 1001)

    def test_empty_rpm_is_complete_but_failed_shards_are_not(self):
        empty = self.response(source='osquery_rpm')
        self.assertTrue(empty['complete'])
        self.assertEqual(empty['records'], [])
        bad = {'timed_out': False, '_shards': {'total': 2, 'successful': 1, 'failed': 1},
               'aggregations': {'software': {'buckets': []}}}
        result = subprocess.CompletedProcess([], 0, json.dumps(bad).encode(), b'')
        with mock.patch.object(exporter, 'run_bounded_command', return_value=result):
            with self.assertRaises(RuntimeError):
                exporter.execute_request(transport.build_request('osquery_rpm', WINDOW, 500, None))

    def test_linux_metadata_and_cursor_are_required_and_fail_closed(self):
        record, cursor = exporter.normalize_bucket('osquery_deb', bucket())
        for field in ['architecture','package_manager','package_release']:
            bad = dict(record); bad.pop(field)
            with self.assertRaises(ValueError): normalization._normalize_record(bad)
        bad = dict(record, package_release='rpm-only')
        with self.assertRaises(ValueError): normalization._normalize_record(bad)
        with self.assertRaises(ValueError): exporter.validate_cursor({k:v for k,v in cursor.items() if k != 'architecture'}, 'osquery_deb')
        with self.assertRaises(ValueError): broker.validate_software_cursor(dict(cursor, asset='bad\nasset'), 'osquery_deb')

    def test_linux_collection_is_opt_in_and_failed_states_preserve_linux_source(self):
        statuses = workflow._failed_source_statuses({'osquery_deb': {'status': 'failed'}})
        self.assertIn('osquery_rpm', statuses)
        self.assertEqual(statuses['osquery_deb']['status'], 'failed')
        self.assertEqual(len(workflow.SOURCES), 3)

    def test_opt_in_collects_five_sources(self):
        now = dt.datetime(2026, 10, 8, 0, tzinfo=dt.timezone.utc)
        config = {'linux_packages_enabled': True, 'max_collection_seconds': 60,
                  'page_size': 500, 'max_pages_per_source': 10, 'timeout_seconds': 30}
        seen = []
        def fetch(config, source, window, page_size, after, deadline):
            seen.append(source)
            policy = workflow.SOURCE_POLICY[source]
            return {'ok': True, 'contract': workflow.CONTRACT, 'read_only': True,
                    'source': source, 'window': window, 'returned': 0, 'complete': True,
                    'truncated': False, 'after': None, 'records': [],
                    'query_audit': {'index': policy['index'], 'dataset': policy['dataset'], 'query_digest': 'a'*64}}
        result = workflow.collect_snapshot(config, {}, now, page_fetcher=fetch)
        self.assertEqual(set(seen), set(workflow.SOURCES) | set(workflow.LINUX_SOURCES))
        self.assertTrue(result['collection']['complete'])
        self.assertEqual(result['collection']['source_statuses']['osquery_rpm']['freshness'], 'empty')

    def test_duplicate_page_rejected_and_architectures_do_not_create_version_conflicts(self):
        record, _ = exporter.normalize_bucket('osquery_rpm', bucket(release='1.el9'))
        rows, identities = [], set()
        workflow._admit_source_page(rows, identities, [record], '')
        with self.assertRaises(workflow.SoftwareInventoryError):
            workflow._admit_source_page(rows, identities, [record], '')
        arm = dict(record, architecture='aarch64', version='another-version')
        self.assertEqual(projection.annotate_version_conflicts([record, arm]), 0)
        updated = dict(record, package_release='2.el9')
        self.assertEqual(projection.annotate_version_conflicts([record, updated]), 2)
