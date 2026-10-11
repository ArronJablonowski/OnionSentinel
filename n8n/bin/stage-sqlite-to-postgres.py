#!/usr/bin/env python3
"""Lossless, read-only SQLite snapshots into isolated PostgreSQL migration staging.

This is NOT application cutover. Original SQLite types/schema and every row are
preserved; PostgreSQL verifies each row's SHA-256 before marking a snapshot ready.
No live application table, lease or credential is modified.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import uuid

SCHEMA = '''
CREATE SCHEMA IF NOT EXISTS onion_sentinel_migration;
CREATE TABLE IF NOT EXISTS onion_sentinel_migration.snapshots (
 snapshot_id text PRIMARY KEY, store text NOT NULL, status text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
 table_count bigint, row_count bigint);
ALTER TABLE onion_sentinel_migration.snapshots ADD COLUMN IF NOT EXISTS source_manifest text;
CREATE TABLE IF NOT EXISTS onion_sentinel_migration.tables (
 snapshot_id text REFERENCES onion_sentinel_migration.snapshots,
 table_name text, schema_sql text NOT NULL, columns_json text NOT NULL,
 expected_rows bigint NOT NULL, PRIMARY KEY(snapshot_id,table_name));
CREATE TABLE IF NOT EXISTS onion_sentinel_migration.rows (
 snapshot_id text, table_name text, ordinal bigint, payload_json text NOT NULL,
 payload_sha256 text NOT NULL, PRIMARY KEY(snapshot_id,table_name,ordinal),
 FOREIGN KEY(snapshot_id,table_name) REFERENCES onion_sentinel_migration.tables);
'''

def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

def identifier(value):
    return '"' + value.replace('"', '""') + '"'

def encode_row(row):
    values = []
    for value in row:
        if value is None: values.append(['null', None])
        elif isinstance(value, int): values.append(['integer', str(value)])
        elif isinstance(value, float): values.append(['real', value.hex()])
        elif isinstance(value, bytes): values.append(['blob', base64.b64encode(value).decode('ascii')])
        elif isinstance(value, str): values.append(['text', value])
        else: raise ValueError('unsupported SQLite storage type')
    payload = json.dumps(values, ensure_ascii=True, separators=(',', ':'))
    if len(payload) > 64 * 1024 * 1024:
        raise ValueError('oversized row requires a reviewed chunked migration')
    return payload

def decode_row(payload):
    decoders = {'null': lambda _: None, 'integer': int, 'real': float.fromhex,
                'blob': base64.b64decode, 'text': lambda x: x}
    return tuple(decoders[kind](value) for kind, value in json.loads(payload))

def schema_manifest(db):
    """Capture schema objects and internal sequence state from the SAME snapshot."""
    objects = db.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'
    ).fetchall()
    sequence = []
    if any(name == 'sqlite_sequence' for _, name, _, _ in objects):
        sequence = db.execute('SELECT name,seq FROM sqlite_sequence ORDER BY name').fetchall()
    return json.dumps({
        'objects': objects, 'sqlite_sequence': sequence,
        'user_version': db.execute('PRAGMA user_version').fetchone()[0],
        'application_id': db.execute('PRAGMA application_id').fetchone()[0],
        'encoding': db.execute('PRAGMA encoding').fetchone()[0],
    }, ensure_ascii=True, separators=(',', ':'))

def command(container):
    # Existing container secrets remain inside the container environment.
    return ['docker','exec','-i',container,'sh','-ec',
            'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"']

def stage(source, store, container):
    if source.is_symlink() or not source.is_file():
        raise ValueError('source must be an existing regular SQLite file')
    if not store.replace('_','').isalnum():
        raise ValueError('invalid store name')
    snapshot = uuid.uuid4().hex
    total = 0
    with sqlite3.connect(source.resolve().as_uri()+'?mode=ro', uri=True, timeout=2) as db:
        db.execute('BEGIN')
        manifest = schema_manifest(db)
        schema = db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
        # Fail atomically. Never expose payload-bearing COPY diagnostics in logs.
        with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as output:
            process = subprocess.Popen(command(container), stdin=subprocess.PIPE, stdout=output, stderr=errors)
            def send(text): process.stdin.write(text.encode('utf-8'))
            try:
                send('BEGIN;\n'+SCHEMA+'\n')
                send('INSERT INTO onion_sentinel_migration.snapshots(snapshot_id,store,status,source_manifest) VALUES ('+
                     quote(snapshot)+','+quote(store)+",'copying',"+quote(manifest)+');\n')
                for name, ddl in schema:
                    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name):
                        raise ValueError('table name requires a reviewed migration')
                    columns = db.execute('PRAGMA table_info('+identifier(name)+')').fetchall()
                    count = db.execute('SELECT count(*) FROM '+identifier(name)).fetchone()[0]
                    send('INSERT INTO onion_sentinel_migration.tables VALUES ('+quote(snapshot)+','+quote(name)+','+
                         quote(ddl or '')+','+quote(json.dumps(columns))+','+str(count)+');\n')
                    send("COPY onion_sentinel_migration.rows FROM STDIN WITH (FORMAT csv, DELIMITER E'\\t', QUOTE E'\\x01', ESCAPE E'\\x01');\n")
                    ordinal = 0
                    cursor = db.execute('SELECT * FROM '+identifier(name))
                    while True:
                        batch = cursor.fetchmany(10)
                        if not batch: break
                        for row in batch:
                            payload = encode_row(row)
                            digest = hashlib.sha256(payload.encode('utf-8')).hexdigest()
                            send(snapshot+'\t'+name+'\t'+str(ordinal)+'\t'+payload+'\t'+digest+'\n')
                            ordinal += 1
                    send('\\.\n')
                    if ordinal != count: raise ValueError('snapshot row count changed')
                    total += ordinal
                send("DO $$ BEGIN IF EXISTS (SELECT 1 FROM onion_sentinel_migration.rows WHERE snapshot_id="+quote(snapshot)+
                     " AND encode(sha256(convert_to(payload_json,'UTF8')),'hex')<>payload_sha256) THEN RAISE EXCEPTION 'row checksum mismatch'; END IF; END $$;\n")
                send("DO $$ BEGIN IF EXISTS (SELECT 1 FROM onion_sentinel_migration.tables t WHERE snapshot_id="+quote(snapshot)+
                     " AND expected_rows<>(SELECT count(*) FROM onion_sentinel_migration.rows r WHERE r.snapshot_id=t.snapshot_id AND r.table_name=t.table_name)) THEN RAISE EXCEPTION 'table count mismatch'; END IF; END $$;\n")
                send("UPDATE onion_sentinel_migration.snapshots SET status='verified_staging_only',completed_at=now(),table_count="+
                     str(len(schema))+',row_count='+str(total)+' WHERE snapshot_id='+quote(snapshot)+';\nCOMMIT;\n')
                process.stdin.close()
                if process.wait(timeout=600) != 0:
                    raise RuntimeError('PostgreSQL staging failed; no snapshot was committed')
            except BaseException:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=30)
                raise
    return {'status':'verified_staging_only','snapshot_id':snapshot,'store':store,
            'tables':len(schema),'rows':total,'application_cutover':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--store',required=True)
    parser.add_argument('--container',default='onion-sentinel-alert-store-postgres')
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    if not args.apply:
        print(json.dumps({'status':'dry_run','application_cutover':False}))
        return 0
    try:
        print(json.dumps(stage(args.source,args.store,args.container),sort_keys=True))
    except Exception:
        print(json.dumps({'status':'failed_no_cutover','application_cutover':False}))
        return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
