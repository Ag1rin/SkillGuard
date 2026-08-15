"""
report.py — Renders SkillReport objects as terminal text, JSON, or Markdown.
"""

import json
import sys
from datetime import datetime, timezone

from .analyzer import VERDICT_SAFE, VERDICT_REVIEW, VERDICT_BLOCKED

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"

VERDICT_STYLE = {
    VERDICT_SAFE: (GREEN, "SAFE"),
    VERDICT_REVIEW: (YELLOW, "REVIEW"),
    VERDICT_BLOCKED: (RED, "BLOCKED"),
}

VERDICT_ICONS = {
    "SAFE": ("\u2713", "+"),
    "REVIEW": ("!", "!"),
    "BLOCKED": ("\u2717", "X"),
}


def _supports_unicode(stream=None):
    stream = stream or sys.stdout
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "\u2713\u2717\u2014\u00b7".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _c(color, text, use_color):
    return f"{color}{text}{RESET}" if use_color else text


def _terminal_text(text, use_unicode):
    if use_unicode:
        return text
    return (
        text.replace("\u2014", "-")
        .replace("\u00b7", "*")
        .replace("\u2713", "+")
        .replace("\u2717", "X")
    )


def render_terminal(reports, use_color=True, use_unicode=None):
    if use_unicode is None:
        use_unicode = _supports_unicode()

    lines = []
    lines.append(_c(BOLD, _terminal_text("SkillGuard — Skill Security Scan", use_unicode), use_color))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(_c(DIM, _terminal_text(f"Scanned {len(reports)} skill(s) · {ts}", use_unicode), use_color))
    lines.append("")

    counts = {VERDICT_SAFE: 0, VERDICT_REVIEW: 0, VERDICT_BLOCKED: 0}

    for r in sorted(reports, key=lambda x: -x.score):
        color, label = VERDICT_STYLE[r.verdict]
        counts[r.verdict] += 1
        icon = VERDICT_ICONS[label][0 if use_unicode else 1]
        lines.append(
            f"{_c(color, f'[{icon}] {label:8s}', use_color)} {_c(BOLD, r.name, use_color)}  "
            f"{_c(DIM, f'(score {r.score}, {r.files_scanned} files, sha256:{r.sha256[:10]})', use_color)}"
        )

        if not r.has_frontmatter:
            lines.append(f"    {_c(YELLOW, '! no YAML frontmatter found in SKILL.md', use_color)}")

        for f in sorted(r.findings, key=lambda x: -x.severity)[:25]:
            sev_color = RED if f.severity >= 15 else (YELLOW if f.severity >= 7 else DIM)
            lines.append(
                f"    {_c(sev_color, f'{f.rule_id}', use_color)} "
                f"{_c(DIM, f'{f.file}:{f.line}', use_color)}  {f.description}"
            )
            if f.snippet:
                lines.append(f"        {_c(DIM, f'> {f.snippet}', use_color)}")
        if len(r.findings) > 25:
            lines.append(f"    {_c(DIM, f'... and {len(r.findings) - 25} more findings', use_color)}")
        lines.append("")

    lines.append(_c(BOLD, "Summary", use_color))
    lines.append(
        f"  {_c(GREEN, f'SAFE: {counts[VERDICT_SAFE]}', use_color)}   "
        f"{_c(YELLOW, f'REVIEW: {counts[VERDICT_REVIEW]}', use_color)}   "
        f"{_c(RED, f'BLOCKED: {counts[VERDICT_BLOCKED]}', use_color)}"
    )
    return "\n".join(lines)


def to_dict(reports):
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "skill_count": len(reports),
        "skills": [
            {
                "name": r.name,
                "path": r.path,
                "verdict": r.verdict,
                "score": r.score,
                "sha256": r.sha256,
                "files_scanned": r.files_scanned,
                "has_frontmatter": r.has_frontmatter,
                "declared_description": r.declared_description,
                "allowed_domains": r.allowed_domains,
                "findings_by_category": r.counts_by_category,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "category": f.category,
                        "severity": f.severity,
                        "file": f.file,
                        "line": f.line,
                        "snippet": f.snippet,
                        "description": f.description,
                    }
                    for f in r.findings
                ],
            }
            for r in reports
        ],
    }


def render_json(reports):
    return json.dumps(to_dict(reports), indent=2)


def render_markdown(reports):
    lines = ["# SkillGuard Report", ""]
    lines.append(f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · {len(reports)} skill(s) scanned_")
    lines.append("")
    lines.append("| Skill | Verdict | Score | Files | Findings |")
    lines.append("|---|---|---|---|---|")
    for r in sorted(reports, key=lambda x: -x.score):
        lines.append(f"| {r.name} | {r.verdict} | {r.score} | {r.files_scanned} | {len(r.findings)} |")
    lines.append("")

    for r in sorted(reports, key=lambda x: -x.score):
        lines.append(f"## {r.name} — {r.verdict}")
        lines.append(f"`sha256:{r.sha256}`")
        lines.append("")
        if not r.findings:
            lines.append("No issues detected.")
        for f in sorted(r.findings, key=lambda x: -x.severity):
            lines.append(f"- **{f.rule_id}** (`{f.category}`, severity {f.severity}) — {f.file}:{f.line}")
            lines.append(f"  {f.description}")
            if f.snippet:
                lines.append(f"  ```\n  {f.snippet}\n  ```")
        lines.append("")
    return "\n".join(lines)
