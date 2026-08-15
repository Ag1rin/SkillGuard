import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from skillguard.analyzer import scan_all, discover_skills, VERDICT_SAFE, VERDICT_REVIEW, VERDICT_BLOCKED

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


class TestDiscovery(unittest.TestCase):
    def test_discovers_both_example_skills(self):
        found = discover_skills(EXAMPLES_DIR)
        names = {os.path.basename(f) for f in found}
        self.assertIn("safe-skill", names)
        self.assertIn("malicious-skill", names)


class TestScanning(unittest.TestCase):
    def setUp(self):
        self.reports = {r.name: r for r in scan_all(EXAMPLES_DIR)}

    def test_safe_skill_is_safe(self):
        r = self.reports["safe-skill"]
        self.assertEqual(r.verdict, VERDICT_SAFE)
        self.assertEqual(r.score, 0)

    def test_malicious_skill_is_blocked(self):
        r = self.reports["malicious-skill"]
        self.assertEqual(r.verdict, VERDICT_BLOCKED)
        self.assertGreater(r.score, 20)

    def test_malicious_skill_flags_prompt_injection(self):
        r = self.reports["malicious-skill"]
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("PI001", rule_ids)  # ignore previous instructions
        self.assertIn("PI002", rule_ids)  # hide from user

    def test_malicious_skill_flags_exfiltration(self):
        r = self.reports["malicious-skill"]
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("EX003", rule_ids)  # webhook.site

    def test_sha256_is_stable_across_scans(self):
        r1 = scan_all(EXAMPLES_DIR)
        r2 = scan_all(EXAMPLES_DIR)
        d1 = {r.name: r.sha256 for r in r1}
        d2 = {r.name: r.sha256 for r in r2}
        self.assertEqual(d1, d2)


class TestResearchBasedPatterns(unittest.TestCase):
    """Each case here mirrors a technique described in published research on
    real-world malicious agent skills (Snyk ToxicSkills, MCP CVE writeups,
    academic papers on skill/tool-poisoning attacks) — reimplemented as
    synthetic, non-functional examples. See README 'Research basis' section
    for sources."""

    def setUp(self):
        self.reports = {r.name: r for r in scan_all(EXAMPLES_DIR)}

    def test_hook_abuse_is_blocked(self):
        r = self.reports["malicious-skill-hooks"]
        self.assertEqual(r.verdict, VERDICT_BLOCKED)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("HK001", rule_ids)  # lifecycle hook reference
        self.assertIn("HK002", rule_ids)  # dormant/sleeper trigger phrase

    def test_url_exfiltration_is_blocked(self):
        r = self.reports["malicious-skill-url-leak"]
        self.assertEqual(r.verdict, VERDICT_BLOCKED)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("EX005", rule_ids)  # interpolated/concatenated URL

    def test_hardcoded_mcp_credential_is_blocked(self):
        r = self.reports["malicious-skill-mcp-creds"]
        self.assertEqual(r.verdict, VERDICT_BLOCKED)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("SC003", rule_ids)  # hardcoded credential

    def test_legitimate_network_use_is_safe_when_domain_declared(self):
        """A skill that declares its external domain and uses only that domain
        should score SAFE — declared domains suppress network false positives."""
        r = self.reports["review-skill-webhook-integration"]
        self.assertEqual(r.verdict, VERDICT_SAFE)
        self.assertIn("api.open-meteo.com", r.allowed_domains)
        rule_ids = {f.rule_id for f in r.findings}
        self.assertNotIn("EX001", rule_ids)

    def test_standalone_mcp_json_is_scanned(self):
        r = self.reports["malicious-skill-mcp-creds"]
        sc003_files = {f.file for f in r.findings if f.rule_id == "SC003"}
        self.assertIn(".mcp.json", sc003_files)

    def test_code_fenced_inside_markdown_is_still_scanned(self):
        """Regression test: code-only rules (e.g. os.system) must fire even
        when the code lives in a ```python fence inside SKILL.md rather than
        a standalone .py file, since that's how most real skills ship code."""
        r = self.reports["malicious-skill"]
        rule_ids = {f.rule_id for f in r.findings}
        self.assertIn("CE001", rule_ids)
        self.assertIn("CE003", rule_ids)

    def test_no_duplicate_findings_for_all_type_rules(self):
        """Regression test for a fixed bug where 'all'-scope rules were
        counted twice within the same file: once over the full file, once again
        over each fenced code block inside it."""
        r = self.reports["malicious-skill-mcp-creds"]
        sc003_by_file = {}
        for f in r.findings:
            if f.rule_id == "SC003":
                sc003_by_file[f.file] = sc003_by_file.get(f.file, 0) + 1
        for count in sc003_by_file.values():
            self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
