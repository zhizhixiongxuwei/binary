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


class CheckerRuleRegressionTests(unittest.TestCase):
    def analyze(self, content):
        return checker.analyze({
            "version": "checker-v1",
            "projectId": "rule-project",
            "language": "python",
            "files": [{"path": "rules.py", "content": content}],
        })

    def rule_ids(self, content):
        return {finding["ruleId"] for finding in self.analyze(content)["findings"]}

    def test_restores_binary_new_rule_families(self):
        content = """\
import hashlib
import os
import pickle
import requests
import subprocess
import yaml

eval(user_input)
os.system(user_input)
subprocess.call(user_input, shell=True)
pickle.loads(raw)
yaml.loads(raw)
hashlib.md5(raw).hexdigest()
requests.get(url, verify=False)
"""
        self.assertEqual({
            "python-dynamic-code-execution",
            "python-command-injection",
            "python-unsafe-deserialization",
            "python-weak-message-digest",
            "python-insecure-request",
        }, self.rule_ids(content))

    def test_resolves_import_aliases_and_from_imports(self):
        content = """\
import hashlib as hashes
import requests as http
from subprocess import check_output as run_command

hashes.sha1(data)
http.post(url, verify=False)
run_command(user_input)
"""
        self.assertEqual({
            "python-command-injection",
            "python-weak-message-digest",
            "python-insecure-request",
        }, self.rule_ids(content))

    def test_safe_forms_have_no_findings(self):
        content = """\
import hashlib
import os
import requests

hashlib.sha256(data).hexdigest()
requests.get(url, verify=True)
os.path.join('a', 'b')
"""
        self.assertEqual(set(), self.rule_ids(content))

    def test_understands_pycdc_keyword_rendering(self):
        content = """\
import requests
import subprocess

subprocess.Popen(command, True, **('shell',))
requests.get(url, False, **('verify',))
"""
        self.assertEqual({
            "python-command-injection",
            "python-insecure-request",
        }, self.rule_ids(content))

    def test_syntax_error_is_partial_without_masking_other_files(self):
        result = checker.analyze({
            "version": "checker-v1",
            "projectId": "partial-project",
            "language": "python",
            "files": [
                {"path": "unsafe.py", "content": "eval(user_input)\n"},
                {"path": "broken.py", "content": "def broken(:\n"},
            ],
        })
        self.assertEqual("partial", result["status"])
        self.assertEqual(1, len(result["diagnostics"]))
        self.assertIn("python-dynamic-code-execution", {
            finding["ruleId"] for finding in result["findings"]
        })


if __name__ == "__main__":
    unittest.main()
