"""Keep only two completed generations, without touching live databases."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'n8n/bin/maintain-alert-store-sqlite.zsh'

class RollingBackupRetentionTests(unittest.TestCase):
    def test_two_is_the_default_for_both_backup_jobs(self):
        self.assertIn('DEFAULT_KEEP_BACKUPS=2', SCRIPT.read_text())
        self.assertIn('parser.add_argument("--keep", type=int, default=2)',
                      (ROOT/'n8n/bin/backup-onion-sentinel-runtime.py').read_text())

    def test_sqlite_pruning_keeps_two_newest_snapshot_pairs(self):
        source = SCRIPT.read_text()
        function = 'prune_backups() {' + source.split('prune_backups() {', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in range(5):
                for extension in ('json','enc'):
                    path = root/f'alerts.sqlite3.20261009T0{number}0000-0600.backup.{extension}'
                    path.write_text('fixture')
                    os.utime(path, (100+number,100+number))
            live = root/'alerts.sqlite3'; live.write_text('live fixture')
            command = 'DEFAULT_KEEP_BACKUPS=2; KEEP_BACKUPS=2; BACKUP_DIR=$1; log() { :; };\n' + function + 'prune_backups'
            result = subprocess.run(['/bin/zsh','-c',command,'retention-test',directory],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(list(root.glob('*.backup.json'))),2)
            self.assertEqual(len(list(root.glob('*.backup.enc'))),2)
            self.assertTrue((root/'alerts.sqlite3.20261009T040000-0600.backup.json').exists())
            self.assertEqual(live.read_text(),'live fixture')

    def test_runtime_bundle_pruning_keeps_two_newest_generations(self):
        spec = importlib.util.spec_from_file_location('rolling_runtime_backup', ROOT/'n8n/bin/backup-onion-sentinel-runtime.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in range(5):
                folder=root/f'20261009T0{number}0000-0600'; folder.mkdir()
                (folder/'fixture.txt').write_text('fixture')
            lock=root/'.backup.lock'; lock.write_text('lock fixture')
            module.prune(root,2)
            self.assertEqual(sorted(p.name for p in root.iterdir() if p.is_dir()),
                             ['20261009T030000-0600','20261009T040000-0600'])
            self.assertTrue(lock.exists())
