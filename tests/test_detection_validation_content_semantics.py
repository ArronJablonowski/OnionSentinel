from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
SCRIPT = BIN / "detection_validation_packet_content.py"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "detection_validation_content_semantics_under_test",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DetectionValidationContentSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_nonnegative_modifier_conversion_is_exact(self):
        cases = (
            (None, None),
            ("", None),
            (0, None),
            (False, None),
            (True, None),
            (" 2 ", 2),
            ("00", 0),
            (3, 3),
            (-1, None),
            (1.0, None),
            ("1.0", None),
            ("+1", None),
        )
        for supplied, expected in cases:
            with self.subTest(supplied=supplied):
                self.assertEqual(
                    self.module._nonnegative_modifier(supplied),
                    expected,
                )

    def test_support_policy_preserves_source_buffer_and_modifier_rules(self):
        cases = (
            ({"source": "playbook"}, None, True),
            ({"source": None, "buffer": "dns.query"}, None, True),
            ({"source": "deployed_rule", "buffer": ""}, None, True),
            ({"source": "deployed_rule", "buffer": " PKT_DATA "}, None, True),
            ({"source": "deployed_rule", "buffer": "dns.query"}, None, False),
            (
                {"source": "deployed_rule", "modifiers": {"dotprefix": True}},
                None,
                False,
            ),
            (
                {"source": "deployed_rule", "modifiers": {"bsize": "4"}},
                None,
                False,
            ),
            (
                {"source": "deployed_rule", "modifiers": {"rawbytes": False}},
                None,
                False,
            ),
            (
                {
                    "source": "deployed_rule",
                    "buffer": "http.host",
                    "modifiers": {"dotprefix": True, "bsize": "4"},
                },
                "http.host",
                True,
            ),
            (
                {"source": "deployed_rule", "buffer": "HTTP.HOST"},
                "http.host",
                True,
            ),
            (
                {"source": "deployed_rule", "buffer": "http.host"},
                "HTTP.HOST",
                False,
            ),
            (
                {
                    "source": "deployed_rule",
                    "buffer": "http.host",
                    "modifiers": {"bsize": 0},
                },
                "http.host",
                False,
            ),
            (
                {
                    "source": "deployed_rule",
                    "buffer": "http.host",
                    "modifiers": [],
                },
                "http.host",
                True,
            ),
        )
        for spec, application_buffer, expected in cases:
            with self.subTest(spec=spec, application_buffer=application_buffer):
                before = copy.deepcopy(spec)
                self.assertIs(
                    self.module._content_evaluation_supported(
                        spec,
                        application_buffer=application_buffer,
                    ),
                    expected,
                )
                self.assertEqual(spec, before)

    def test_absolute_content_bounds_preserve_clamping_and_invalid_states(self):
        payload = b"0123456789"
        cases = (
            ({}, (0, 10)),
            ({"offset": "2"}, (2, 10)),
            ({"depth": "3"}, (0, 3)),
            ({"offset": "2", "depth": "3"}, (2, 5)),
            ({"offset": "12", "depth": "3"}, (12, 10)),
            ({"offset": 0}, None),
            ({"depth": -1}, None),
            ({"offset": "bad"}, None),
        )
        for modifiers, expected in cases:
            with self.subTest(modifiers=modifiers):
                before = copy.deepcopy(modifiers)
                self.assertEqual(
                    self.module._content_bounds(
                        payload,
                        modifiers,
                        previous_match_end=None,
                    ),
                    expected,
                )
                self.assertEqual(modifiers, before)

    def test_relative_bounds_require_cursor_and_reject_absolute_mixing(self):
        payload = b"0123456789"
        cases = (
            ({"distance": "2"}, None, None),
            ({"within": "4"}, None, None),
            ({"distance": "2"}, 3, (5, 10)),
            ({"within": "4"}, 3, (3, 7)),
            ({"distance": "2", "within": "4"}, 3, (5, 9)),
            ({"distance": "20", "within": "4"}, 3, (23, 10)),
            ({"distance": "bad"}, 3, None),
            ({"within": 0}, 3, None),
            ({"distance": "1", "offset": "2"}, 3, None),
            ({"within": "3", "depth": "2"}, 3, None),
        )
        for modifiers, previous_end, expected in cases:
            with self.subTest(modifiers=modifiers, previous_end=previous_end):
                self.assertEqual(
                    self.module._content_bounds(
                        payload,
                        modifiers,
                        previous_match_end=previous_end,
                    ),
                    expected,
                )

    def test_anchored_positions_preserve_precedence_bounds_and_nocase(self):
        payload = b"Abc---abc"
        cases = (
            (b"abc", {"startswith": True, "nocase": True}, 0, 9, [0]),
            (b"Abc", {"startswith": True}, -1, 3, [0]),
            (b"Abc", {"startswith": True}, 1, 9, []),
            (b"abc", {"endswith": True}, 0, 9, [6]),
            (b"ABC", {"endswith": True, "nocase": True}, 6, 9, [6]),
            (b"abc", {"endswith": True}, 7, 9, []),
            (
                b"Abc---abc",
                {"startswith": True, "endswith": True},
                0,
                9,
                [0],
            ),
            (b"abc", {}, 0, 9, None),
        )
        for marker, modifiers, start, end, expected in cases:
            with self.subTest(marker=marker, modifiers=modifiers):
                self.assertEqual(
                    self.module._anchored_content_positions(
                        payload,
                        marker,
                        modifiers,
                        start=start,
                        end=end,
                    ),
                    expected,
                )

    def test_find_positions_preserves_overlap_bounds_and_match_budget(self):
        limit = self.module.MAX_MARKER_MATCHES_PER_PACKET
        self.assertEqual(
            self.module._find_content_positions(
                b"aaaa",
                b"aa",
                {},
                start=0,
                end=4,
            ),
            [0, 1, 2],
        )
        self.assertEqual(
            self.module._find_content_positions(
                b"xxABCabc",
                b"abc",
                {"nocase": True},
                start=2,
                end=8,
            ),
            [2, 5],
        )
        self.assertEqual(
            self.module._find_content_positions(
                b"a" * (limit + 20),
                b"a",
                {},
                start=0,
                end=limit + 20,
            ),
            list(range(limit)),
        )
        for start, end in ((-1, 2), (5, 4), (10, 11)):
            with self.subTest(start=start, end=end):
                self.assertEqual(
                    self.module._find_content_positions(
                        b"abc",
                        b"a",
                        {},
                        start=start,
                        end=end,
                    ),
                    [],
                )

    def test_match_positions_distinguish_unsupported_absent_and_present(self):
        payload = b"xxABCyDEFzz"
        cases = (
            (
                b"ABC",
                {"source": "deployed_rule", "buffer": "dns.query"},
                None,
                None,
            ),
            (
                b"ABC",
                {
                    "source": "deployed_rule",
                    "buffer": "http.host",
                    "modifiers": {"bsize": "12"},
                },
                [],
                "http.host",
            ),
            (
                b"ABC",
                {
                    "source": "deployed_rule",
                    "buffer": "http.host",
                    "modifiers": {"bsize": "11"},
                },
                [2],
                "http.host",
            ),
            (
                b"ABC",
                {"source": "deployed_rule", "modifiers": {"offset": "2"}},
                [2],
                None,
            ),
            (
                b"DEF",
                {
                    "source": "deployed_rule",
                    "modifiers": {"distance": "1", "within": "4"},
                },
                [6],
                None,
            ),
        )
        for marker, spec, expected, application_buffer in cases:
            with self.subTest(marker=marker, spec=spec):
                kwargs = {"application_buffer": application_buffer}
                if "distance" in spec.get("modifiers", {}):
                    kwargs["previous_match_end"] = 5
                self.assertEqual(
                    self.module._content_match_positions(
                        payload,
                        marker,
                        spec,
                        **kwargs,
                    ),
                    expected,
                )

    def test_constraint_preserves_negation_and_unknown_projection(self):
        payload = b"abc"
        base = {"source": "deployed_rule", "modifiers": {}}
        self.assertTrue(self.module._content_constraint(payload, b"a", base))
        self.assertFalse(self.module._content_constraint(payload, b"z", base))
        self.assertFalse(
            self.module._content_constraint(
                payload,
                b"a",
                {**base, "negated": True},
            )
        )
        self.assertTrue(
            self.module._content_constraint(
                payload,
                b"z",
                {**base, "negated": True},
            )
        )
        self.assertIsNone(
            self.module._content_constraint(
                payload,
                b"a",
                {**base, "buffer": "dns.query"},
            )
        )

    def test_ordered_constraints_preserve_cursor_unknown_and_buffer_resets(self):
        payload = b"ABxxCDyyEF"
        marker_values = [
            (
                {"id": "skip", "source": "playbook", "modifiers": {}},
                b"AB",
            ),
            (
                {
                    "id": "first",
                    "source": "deployed_rule",
                    "buffer": "pkt_data",
                    "modifiers": {},
                },
                b"AB",
            ),
            (
                {
                    "id": "relative-hit",
                    "source": "deployed_rule",
                    "buffer": "pkt_data",
                    "modifiers": {"distance": "2", "within": "2"},
                },
                b"CD",
            ),
            (
                {
                    "id": "relative-miss",
                    "source": "deployed_rule",
                    "buffer": "pkt_data",
                    "modifiers": {"within": "1"},
                },
                b"EF",
            ),
            (
                {
                    "id": "relative-after-miss",
                    "source": "deployed_rule",
                    "buffer": "pkt_data",
                    "modifiers": {"distance": "0"},
                },
                b"EF",
            ),
            (
                {
                    "id": "buffer-reset",
                    "source": "deployed_rule",
                    "buffer": "http.host",
                    "modifiers": {},
                },
                b"EF",
            ),
            (
                {
                    "id": "unsupported",
                    "source": "deployed_rule",
                    "buffer": "dns.query",
                    "modifiers": {},
                },
                b"AB",
            ),
            (
                {
                    "id": "unknown-relative",
                    "source": "deployed_rule",
                    "buffer": "dns.query",
                    "modifiers": {"within": "2"},
                },
                b"CD",
            ),
        ]
        before = copy.deepcopy(marker_values)
        result = self.module._ordered_deployed_content_constraints(
            payload,
            marker_values,
        )
        self.assertEqual(
            result,
            {
                "first": True,
                "relative-hit": True,
                "relative-miss": False,
                "relative-after-miss": False,
                "buffer-reset": None,
                "unsupported": None,
                "unknown-relative": None,
            },
        )
        self.assertEqual(list(result), list(result.keys()))
        self.assertEqual(marker_values, before)

    def test_ordered_constraints_preserve_errors_and_negated_cursor(self):
        with self.assertRaises(KeyError) as raised:
            self.module._ordered_deployed_content_constraints(
                b"abc",
                [({"source": "deployed_rule", "modifiers": {}}, b"a")],
            )
        self.assertEqual(raised.exception.args, ("id",))

        marker_values = [
            (
                {
                    "id": "negated",
                    "source": "deployed_rule",
                    "buffer": "pkt_data",
                    "modifiers": {},
                    "negated": True,
                },
                b"z",
            ),
            (
                {
                    "id": "relative",
                    "source": "deployed_rule",
                    "buffer": "pkt_data",
                    "modifiers": {"distance": "0"},
                },
                b"a",
            ),
        ]
        self.assertEqual(
            self.module._ordered_deployed_content_constraints(
                b"abc",
                marker_values,
            ),
            {"negated": True, "relative": None},
        )


if __name__ == "__main__":
    unittest.main()
