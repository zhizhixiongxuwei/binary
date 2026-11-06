import sys
import hashlib
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
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
        for rule_id in checker.RULE_IDS:
            selected = checker.analyze({
                "version": "checker-v1", "projectId": "selection", "language": "python",
                "files": [{"path": "rules.py", "content": content}],
                "ruleIds": [rule_id], "catalogVersion": checker.CATALOG_VERSION,
            })
            self.assertEqual({rule_id}, {finding["ruleId"] for finding in selected["findings"]})
            self.assertEqual([rule_id], selected["appliedRuleIds"])
            self.assertEqual([], selected["diagnostics"])

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


class RuleSelectionContractTests(unittest.TestCase):
    def request(self, **overrides):
        return {"version": "checker-v1", "projectId": "selection", "language": "python", "files": [], **overrides}

    def test_catalog_fingerprints_complete_metadata_and_keeps_default_all(self):
        catalog = checker.rule_catalog()
        self.assertEqual(5, len(catalog["rules"]))
        self.assertEqual(checker.RULE_IDS, {rule["id"] for rule in catalog["rules"]})
        canonical = json.dumps(catalog["rules"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual("sha256:" + hashlib.sha256(canonical).hexdigest(), catalog["catalogVersion"])
        for rule in catalog["rules"]:
            self.assertEqual("python", rule["language"])
            self.assertTrue(rule["name"] and rule["description"] and rule["limitations"] and rule["cwes"])
            self.assertTrue(rule["default_enabled"])
        result = checker.analyze(self.request())
        self.assertEqual(sorted(checker.RULE_IDS), result["appliedRuleIds"])
        self.assertEqual(checker.CATALOG_VERSION, result["catalogVersion"])
        catalog["rules"][0]["name"] = "修改调用方副本"
        self.assertNotEqual(catalog["rules"][0]["name"], checker.rule_catalog()["rules"][0]["name"])

    def test_rejects_empty_unknown_wrong_language_stale_and_malformed_selection(self):
        for ids in ([], None, "python-command-injection", [1], ["unknown"], ["java-command-injection"]):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                checker.analyze(self.request(ruleIds=ids))
        for version in (None, "checker-v1", "sha256:outdated", 1):
            with self.subTest(version=version), self.assertRaises(ValueError):
                checker.analyze(self.request(catalogVersion=version))
        result = checker.analyze(self.request(ruleIds=["python-command-injection"] * 2, catalogVersion=checker.CATALOG_VERSION))
        self.assertEqual(["python-command-injection"], result["appliedRuleIds"])

    def test_disabled_rules_are_not_evaluated(self):
        # This helper belongs only to the TLS rule. A filter applied after a full
        # analysis would still call it and fail this test.
        with patch.object(checker, "has_keyword_false", side_effect=AssertionError("disabled TLS rule ran")):
            result = checker.analyze(self.request(
                files=[{"path": "rules.py", "content": "import requests\nrequests.get(url, verify=False)\neval(text)\n"}],
                ruleIds=["python-dynamic-code-execution"],
            ))
        self.assertEqual(["python-dynamic-code-execution"], [finding["ruleId"] for finding in result["findings"]])

    def test_http_catalog_selection_and_validation(self):
        server = checker.ThreadingHTTPServer(("127.0.0.1", 0), checker.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with urlopen(base + "/v1/rules", timeout=2) as response:
                catalog = json.load(response)
            self.assertEqual(checker.CATALOG_VERSION, catalog["catalogVersion"])
            body = json.dumps(self.request(ruleIds=["python-command-injection"], catalogVersion=catalog["catalogVersion"])).encode()
            with urlopen(Request(base + "/v1/check", data=body, headers={"Content-Type": "application/json"}), timeout=2) as response:
                self.assertEqual(["python-command-injection"], json.load(response)["appliedRuleIds"])
            with self.assertRaises(HTTPError) as rejected:
                urlopen(Request(base + "/v1/check", data=json.dumps(self.request(ruleIds=[])).encode(), headers={"Content-Type": "application/json"}), timeout=2)
            self.assertEqual(400, rejected.exception.code)
            rejected.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
