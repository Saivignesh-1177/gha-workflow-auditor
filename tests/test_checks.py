import unittest
from pathlib import Path

import yaml

from ghaudit.__main__ import audit_file, to_sarif

EX = Path(__file__).resolve().parents[1] / "examples"


def rules_for(yaml_text: str) -> set[str]:
    from ghaudit.checks import ALL_CHECKS
    wf = yaml.safe_load(yaml_text)
    return {f.rule for c in ALL_CHECKS for f in c(wf, yaml_text)}


BASE = "permissions: {contents: read}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"


class Examples(unittest.TestCase):
    def test_vulnerable_example_hits_every_rule(self):
        found = {f.rule for f in audit_file(EX / "vulnerable.yml")}
        self.assertEqual(found, {f"GHA00{i}" for i in range(1, 9)})

    def test_hardened_example_is_clean(self):
        self.assertEqual(audit_file(EX / "hardened.yml"), [])

    def test_sarif_shape(self):
        sarif = to_sarif({EX / "vulnerable.yml": audit_file(EX / "vulnerable.yml")})
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])


class Checks(unittest.TestCase):
    def test_on_key_parsed_as_bool(self):
        # YAML 1.1 turns `on:` into True. The trigger detection must still work.
        y = "on: pull_request_target\n" + BASE + \
            "      - uses: actions/checkout@v4\n        with: {ref: '${{ github.head_ref }}', persist-credentials: false}\n"
        self.assertIn("GHA003", rules_for(y))

    def test_checkout_without_ref_under_prt_is_ok(self):
        y = "on: pull_request_target\n" + BASE + \
            "      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n"
        self.assertNotIn("GHA003", rules_for(y))

    def test_env_indirection_not_flagged(self):
        y = "on: issues\n" + BASE + \
            "      - env: {T: '${{ github.event.issue.title }}'}\n        run: echo \"$T\"\n"
        self.assertNotIn("GHA002", rules_for(y))

    def test_github_script_injection(self):
        y = "on: issues\n" + BASE + \
            "      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.body }}')\n"
        self.assertIn("GHA002", rules_for(y))

    def test_safe_contexts_not_flagged(self):
        y = "on: push\n" + BASE + "      - run: echo ${{ github.sha }} ${{ github.event.pull_request.number }}\n"
        self.assertNotIn("GHA002", rules_for(y))

    def test_write_all(self):
        self.assertIn("GHA004", rules_for("on: push\npermissions: write-all\njobs: {}\n"))

    def test_local_and_docker_actions_not_pin_checked(self):
        y = "on: push\n" + BASE + "      - uses: ./.github/actions/x\n      - uses: docker://alpine:3\n"
        self.assertNotIn("GHA001", rules_for(y))


if __name__ == "__main__":
    unittest.main()
