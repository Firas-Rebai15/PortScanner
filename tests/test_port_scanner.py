import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from port_scanner import parse_ports


class ParsePortsTests(unittest.TestCase):
    def test_deduplicates_and_sorts(self):
        self.assertEqual(parse_ports("80,22,80,443-445"), [22, 80, 443, 444, 445])


    def test_rejects_invalid_specs(self):
        for spec in ("0", "65536", "10-2", ""):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    parse_ports(spec)


if __name__ == "__main__":
    unittest.main()
