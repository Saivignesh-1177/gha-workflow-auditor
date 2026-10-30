# GitHub Actions Workflow Auditor (`ghaudit`)

![ci](https://github.com/Saivignesh-1177/gha-workflow-auditor/actions/workflows/ci.yml/badge.svg)

CI/CD pipelines hold the keys to production, which makes them a prime supply-chain target (OWASP **CICD-SEC
Top 10**, SLSA). `ghaudit` statically audits GitHub Actions workflows for the misconfigurations behind real
incidents, and it emits **SARIF** so the findings show up in GitHub code scanning.

## Checks

| Rule | Finding | Real-world precedent |
|---|---|---|
| GHA001 | Action pinned to a mutable tag or branch instead of a commit SHA | tj-actions/changed-files compromise (Mar 2025): tags were repointed to secret-dumping code |
| GHA002 | **Script injection**: untrusted `${{ github.event.issue.title }}` / PR body / branch name inside `run:` or `github-script` | A long-running class of GitHub Security Lab advisories |
| GHA003 | **"Pwn request"**: `pull_request_target` / `workflow_run` checks out the PR head | Fork PR code runs with secrets and a write token |
| GHA004 | Missing or `write-all` `permissions:` | Over-privileged GITHUB_TOKEN |
| GHA005 | `actions/checkout` without `persist-credentials: false` | Token left in `.git/config` for later steps or artifacts |
| GHA006 | `curl \| bash` without an integrity check | Codecov bash-uploader compromise (2021) |
| GHA007 | Secret echoed or written to a file | Masking bypass, secrets leaking into artifacts |
| GHA008 | Self-hosted runner reachable from pull requests | Fork PRs persisting on your infrastructure |

## Demo

[`examples/vulnerable.yml`](examples/vulnerable.yml) triggers all 8 rules.
[`examples/hardened.yml`](examples/hardened.yml) is the remediated version and comes back clean.

```
$ python -m ghaudit examples/vulnerable.yml
examples/vulnerable.yml: 9 finding(s)
  CRITICAL GHA002 build/Greet
           Untrusted 'github.event.issue.title' is interpolated into a shell script. Pass it via env: and quote "$VAR".
  CRITICAL GHA003 build/actions/checkout@v4
           Privileged trigger checks out untrusted PR code ('pwn request'). Secrets and a write token are exposed to attacker-controlled code.
  HIGH     GHA001 build/tj-actions/changed-files@v45
           'tj-actions/changed-files@v45' is pinned to a mutable ref. Pin it to a full commit SHA.
  HIGH     GHA007 build/Debug
  ...
$ python -m ghaudit examples/hardened.yml
examples/hardened.yml: 0 finding(s)
```

## Usage

```bash
pip install -r requirements.txt
python -m ghaudit .github/workflows                       # report, exit 1 on high+
python -m ghaudit .github/workflows --fail-on critical --sarif ghaudit.sarif
python -m unittest -v
```

This repo's own CI runs `ghaudit` against itself and uploads the SARIF to code scanning.

## Implementation notes

- Handles the YAML 1.1 quirk where PyYAML parses the bare key `on:` as boolean `True`. A naive parser would
  silently miss every trigger-based rule.
- The script-injection check recognizes the safe `env:` indirection pattern, and it does not flag
  non-attacker-controlled contexts such as `github.sha` or `pull_request.number`.
- Severity is graded: first-party `actions/*` on a tag is *low*, third-party is *high*.

## Limits and next steps

- [ ] Report real line numbers in SARIF (use a YAML loader that keeps positions)
- [ ] Reusable workflows and composite actions (`uses:` across repos)
- [ ] Check that a pinned SHA actually belongs to the claimed upstream repo and tag
