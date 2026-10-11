import importlib.util
import json
import sqlite3
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pg_stage',ROOT/'n8n/bin/stage-sqlite-to-postgres.py')
stage=importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)

class StageTests(unittest.TestCase):
    def test_roundtrip_preserves_types_and_control_characters(self):
        row=(None,2**63-1,-7,1.0,-0.0,b'\0\xff\x01',"a\t\nb'\\c\x01")
        result=stage.decode_row(stage.encode_row(row))
        self.assertEqual(result,row)
        self.assertEqual(result[4].hex(),row[4].hex())
        self.assertIsInstance(result[3],float)
    def test_quotes_are_data_not_sql(self):
        self.assertEqual(stage.quote("x';drop table alerts;--"),"'x'';drop table alerts;--'")
        self.assertEqual(stage.identifier('a"b'),'"a""b"')
    def test_unknown_values_fail_closed(self):
        with self.assertRaises(ValueError): stage.encode_row((object(),))
    def test_manifest_preserves_indexes_triggers_views_and_sequence(self):
        with sqlite3.connect(':memory:') as db:
            db.executescript('''CREATE TABLE data(id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT);
              CREATE INDEX value_idx ON data(value);
              CREATE VIEW data_view AS SELECT * FROM data;
              CREATE TRIGGER value_trigger AFTER INSERT ON data BEGIN SELECT 1; END;
              INSERT INTO data(value) VALUES ('sample'); DELETE FROM data;''')
            manifest = json.loads(stage.schema_manifest(db))
        self.assertTrue({'index','view','trigger','table'} <= {x[0] for x in manifest['objects']})
        self.assertEqual(manifest['sqlite_sequence'], [['data', 1]])
