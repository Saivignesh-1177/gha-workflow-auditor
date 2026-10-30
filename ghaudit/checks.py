"""Security checks for GitHub Actions workflows.

Each check is a function (workflow_dict, raw_text) -> list[Finding]. The checks target the patterns behind
real incidents: tj-actions/changed-files (2025, a mutable tag repointed to malicious code), "pwn request"
pull_request_target abuse, and script injection through issue and PR titles.
"""
import re
from dataclasses import dataclass

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
UNTRUSTED_CTX = re.compile(
    r"\$\{\{\s*("
    r"github\.event\.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment)\.(title|body)"
    r"|github\.event\.pull_request\.head\.(ref|label|repo\.default_branch)"
    r"|github\.event\.head_commit\.(message|author\.(email|name))"
    r"|github\.event\.commits\[?.*?\]?\.(message|author\.(email|name))"
    r"|github\.event\.pages\[?.*?\]?\.page_name"
    r"|github\.head_ref"
    r")\s*\}\}"
)
PR_HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/")
PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b")
SECRET_ECHO = re.compile(r"(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # critical | high | medium | low
    message: str
    job: str = ""
    step: str = ""


def _triggers(wf: dict) -> set[str]:
    on = wf.get("on", wf.get(True))   # PyYAML (YAML 1.1) parses the bare key `on` as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def _steps(wf: dict):
    for job_id, job in (wf.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for i, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                yield job_id, job, step.get("name") or step.get("uses") or f"step {i + 1}", step


def check_unpinned_actions(wf, _raw):
    out = []
    for job_id, _job, name, step in _steps(wf):
        uses = step.get("uses")
        if not uses or uses.startswith(("./", "docker://")):
            continue
        ref = uses.partition("@")[2]
        if not SHA_RE.match(ref):
            first_party = uses.startswith(("actions/", "github/"))
            out.append(Finding("GHA001", "low" if first_party else "high",
                               f"'{uses}' is pinned to a mutable ref. Pin it to a full commit SHA.", job_id, name))
    return out


def check_script_injection(wf, _raw):
    out = []
    for job_id, _job, name, step in _steps(wf):
        for field in ("run",):
            body = step.get(field)
            if isinstance(body, str) and (m := UNTRUSTED_CTX.search(body)):
                out.append(Finding("GHA002", "critical",
                                   f"Untrusted '{m.group(1)}' is interpolated into a shell script. Pass it via env: "
                                   "and quote \"$VAR\".", job_id, name))
        script = (step.get("with") or {}).get("script")
        if isinstance(script, str) and (m := UNTRUSTED_CTX.search(script)):
            out.append(Finding("GHA002", "critical",
                               f"Untrusted '{m.group(1)}' is interpolated into a github-script body.", job_id, name))
    return out


def check_pwn_request(wf, _raw):
    trig = _triggers(wf)
    if not trig & {"pull_request_target", "workflow_run"}:
        return []
    out = []
    for job_id, _job, name, step in _steps(wf):
        if str(step.get("uses", "")).startswith("actions/checkout"):
            ref = str((step.get("with") or {}).get("ref", ""))
            if PR_HEAD_REF.search(ref):
                out.append(Finding("GHA003", "critical",
                                   "Privileged trigger checks out untrusted PR code ('pwn request'). Secrets and a "
                                   "write token are exposed to attacker-controlled code.", job_id, name))
    return out


def check_permissions(wf, _raw):
    out = []
    top = wf.get("permissions")
    if top is None:
        jobs = wf.get("jobs") or {}
        if not all(isinstance(j, dict) and "permissions" in j for j in jobs.values()):
            out.append(Finding("GHA004", "medium",
                               "No 'permissions:' block, so GITHUB_TOKEN gets the repo default (often write-all). "
                               "Declare least privilege, e.g. 'contents: read'."))
    elif top == "write-all":
        out.append(Finding("GHA004", "high", "permissions: write-all grants every scope."))
    return out


def check_persist_credentials(wf, _raw):
    out = []
    for job_id, _job, name, step in _steps(wf):
        if str(step.get("uses", "")).startswith("actions/checkout"):
            if (step.get("with") or {}).get("persist-credentials") is not False:
                out.append(Finding("GHA005", "low",
                                   "checkout leaves GITHUB_TOKEN in .git/config. Set persist-credentials: false.",
                                   job_id, name))
    return out


def check_dangerous_run(wf, _raw):
    out = []
    for job_id, _job, name, step in _steps(wf):
        body = step.get("run")
        if not isinstance(body, str):
            continue
        if PIPE_TO_SHELL.search(body):
            out.append(Finding("GHA006", "medium", "Remote script piped to a shell without integrity check.",
                               job_id, name))
        if SECRET_ECHO.search(body):
            out.append(Finding("GHA007", "high", "A secret is written to stdout or a file. Masking is easy to bypass.",
                               job_id, name))
    return out


def check_self_hosted_on_pr(wf, _raw):
    if not _triggers(wf) & {"pull_request", "pull_request_target"}:
        return []
    out = []
    for job_id, job in (wf.get("jobs") or {}).items():
        runs_on = job.get("runs-on") if isinstance(job, dict) else None
        labels = runs_on if isinstance(runs_on, list) else [runs_on]
        if "self-hosted" in labels:
            out.append(Finding("GHA008", "high",
                               "Self-hosted runner reachable from pull requests. Fork PRs can run code on your "
                               "infrastructure.", job_id))
    return out


ALL_CHECKS = (check_unpinned_actions, check_script_injection, check_pwn_request, check_permissions,
              check_persist_credentials, check_dangerous_run, check_self_hosted_on_pr)
