from __future__ import annotations

import sys
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_agent_content_store import (  # noqa: E402
    AgentMemorySources,
    read_agent_memory,
    read_allowlisted_prompt,
    read_prompt_file,
    save_allowlisted_prompt,
    save_prompt_file,
)


class AgentContentStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_prompt_save_normalizes_newlines_and_is_owner_only(self) -> None:
        path = self.root / "config" / "prompt.md"
        saved, response = save_prompt_file(
            "  line one\r\nline two\r  ",
            path,
            "SOC Analyst",
            max_bytes=100,
        )
        self.assertTrue(saved)
        self.assertEqual(path.read_text(), "line one\nline two\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(response["bytes"], len("line one\nline two\n"))

    def test_prompt_rejects_empty_and_oversized_without_writing(self) -> None:
        path = self.root / "prompt.md"
        for prompt, expected in (("  ", "cannot be empty"), ("éé", "exceeds")):
            with self.subTest(prompt=prompt):
                saved, response = save_prompt_file(
                    prompt, path, "Test", max_bytes=3
                )
                self.assertFalse(saved)
                self.assertIn(expected, response["error"])
                self.assertFalse(path.exists())

    def test_prompt_route_map_is_the_only_path_selector(self) -> None:
        path = self.root / "prompt.md"
        routes = {"/allowed": ("Allowed", path)}
        saved, _ = save_allowlisted_prompt(
            "/allowed", "content", routes, max_bytes=100
        )
        self.assertTrue(saved)
        self.assertEqual(read_allowlisted_prompt("/allowed", routes)["prompt"], "content\n")
        self.assertFalse(read_allowlisted_prompt("/unknown", routes)["ok"])
        saved, _ = save_allowlisted_prompt(
            "/unknown", "content", routes, max_bytes=100
        )
        self.assertFalse(saved)

    def test_missing_prompt_reads_as_empty(self) -> None:
        response = read_prompt_file(self.root / "missing.md", "Missing")
        self.assertTrue(response["ok"])
        self.assertEqual(response["prompt"], "")

    def test_memory_read_is_allowlisted_bounded_and_read_only(self) -> None:
        memory_dir = self.root / "memory"
        memory_dir.mkdir()
        memory = memory_dir / "soc.md"
        memory.write_text("known fact", encoding="utf-8")
        sources = AgentMemorySources(
            directory=memory_dir,
            files={"soc": ("SOC Memory", memory)},
            max_bytes=100,
        )
        status, response = read_agent_memory(sources, " SOC ")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(response["read_only"])
        self.assertEqual(response["content"], "known fact")
        self.assertIn("  ", response["modified_at"])
        status, _ = read_agent_memory(sources, "../memory/soc.md")
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)

    def test_memory_rejects_escape_missing_and_oversize(self) -> None:
        memory_dir = self.root / "memory"
        memory_dir.mkdir()
        outside = self.root / "outside.md"
        outside.write_text("outside", encoding="utf-8")
        link = memory_dir / "link.md"
        link.symlink_to(outside)
        missing = memory_dir / "missing.md"
        large = memory_dir / "large.md"
        large.write_text("12345", encoding="utf-8")
        sources = AgentMemorySources(
            directory=memory_dir,
            files={
                "link": ("Link", link),
                "missing": ("Missing", missing),
                "large": ("Large", large),
            },
            max_bytes=4,
        )
        self.assertEqual(read_agent_memory(sources, "link")[0], HTTPStatus.FORBIDDEN)
        self.assertEqual(read_agent_memory(sources, "missing")[0], HTTPStatus.NOT_FOUND)
        status, response = read_agent_memory(sources, "large")
        self.assertEqual(status, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        self.assertEqual(response["bytes"], 5)


if __name__ == "__main__":
    unittest.main()
