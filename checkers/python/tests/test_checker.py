import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import checker  # noqa: E402


class CheckerCoordinateTests(unittest.TestCase):
    def test_ast_utf8_byte_offset_becomes_monaco_utf16_column(self):
        prefix = "label = '😀中文'; "
        content = prefix + "eval(user_input)\n"
        result = checker.analyze({
            "version": "checker-v1",
            "projectId": "unicode-project",
            "language": "python",
            "files": [{"path": "unicode.py", "content": content}],
        })

        self.assertEqual(1, len(result["findings"]))
        finding = result["findings"][0]
        expected_column = len(prefix.encode("utf-16-le")) // 2 + 1
        self.assertEqual(1, finding["line"])
        self.assertEqual(expected_column, finding["column"])
        self.assertEqual(17, finding["column"])


if __name__ == "__main__":
    unittest.main()
