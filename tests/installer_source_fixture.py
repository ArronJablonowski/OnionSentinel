"""Inspect composed installers without invoking their deployment side effects."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from n8n.install.macstudio_phase_contract import read_installer_source

__all__ = ["read_installer_source"]
