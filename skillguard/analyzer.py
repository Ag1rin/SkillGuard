"""
analyzer.py — Walks skill directories, applies rules, produces findings.
"""

import hashlib
import os
import re
from dataclasses import dataclass, field

from .patterns import RULES

MD_EXTENSIONS = {".md", ".mdx", ".txt"}
CODE_EXTENSIONS = {".py", ".sh", ".js", ".ts", ".rb", ".ps1", ".bash"}
CONFIG_EXTENSIONS = {".json", ".jsonc", ".yaml", ".yml", ".toml"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}

NETWORK_ALLOWLIST_RULES = {"EX001", "EX003", "EX005"}
CONTEXT_WINDOW = 2

DOMAIN_DECL_RE = re.compile(
    r"(?:domain|domains|host|hosts|endpoint|endpoints)\s*(?:is|are|:)\s*"
    r"(?:exactly\s+(?:one|two|three|\d+)\s+)?[`'\"]?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})[`'\"]?",
    re.IGNORECASE,
)
BACKTICK_DOMAIN_RE = re.compile(
    r"`([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)`",
    re.IGNORECASE,
)

VERDICT_SAFE, VERDICT_REVIEW, VERDICT_BLOCKED = "SAFE", "REVIEW", "BLOCKED"


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: int
    file: str
    line: int
    snippet: str
    description: str
    context: str = ""


@dataclass
class SkillReport:
    name: str
    path: str
    findings: list = field(default_factory=list)
    files_scanned: int = 0
    sha256: str = ""
    has_frontmatter: bool = False
    declared_description: str = ""
    allowed_domains: list = field(default_factory=list)

    @property
    def score(self):
        return sum(f.severity for f in self.findings)

    @property
    def verdict(self):
        crit = any(f.severity >= 15 for f in self.findings)
        if crit or self.score >= 20:
            return VERDICT_BLOCKED
        if self.score >= 5:
            return VERDICT_REVIEW
        return VERDICT_SAFE

    @property
    def counts_by_category(self):
        out = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out


def _file_type(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in MD_EXTENSIONS:
        return "md"
    if ext in CODE_EXTENSIONS:
        return "code"
    if ext in CONFIG_EXTENSIONS or os.path.basename(path).lower().endswith(".mcp.json"):
        return "config"
    return None


FENCE_RE = re.compile(r"^```[^\n]*\n(.*?)^```", re.DOTALL | re.MULTILINE)


def _apply_rules(text, lines, line_offset, allowed_types, rel_path, findings):
    for rule in RULES:
        if rule.file_types not in allowed_types:
            continue
        for match in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1 + line_offset
            local_idx = line_no - line_offset - 1
            line_text = lines[local_idx].strip() if 0 <= local_idx < len(lines) else ""
            snippet = (line_text[:117] + "...") if len(line_text) > 120 else line_text
            ctx_start = max(0, local_idx - CONTEXT_WINDOW)
            ctx_end = min(len(lines), local_idx + CONTEXT_WINDOW + 1)
            context = "\n".join(lines[ctx_start:ctx_end])
            findings.append(Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                file=rel_path,
                line=line_no,
                snippet=snippet,
                description=rule.description,
                context=context,
            ))


def _scan_file(path, rel_path, findings):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return

    ftype = _file_type(path)
    if ftype is None:
        return

    lines = text.splitlines()

    # Pass 1: rules that apply to this file's own type ('all' or 'md'/'code').
    _apply_rules(text, lines, 0, {"all", ftype}, rel_path, findings)

    # Pass 2: SKILL.md (and other markdown) commonly embeds code directly in
    # fenced blocks rather than as separate .py/.sh files. Extract those
    # blocks and run 'code' rules against them too, so an `os.system(...)`
    # written inline in SKILL.md is caught exactly like it would be in a
    # standalone script. Line numbers are offset back to the original file.
    if ftype == "md":
        for m in FENCE_RE.finditer(text):
            block = m.group(1)
            block_start_line = text.count("\n", 0, m.start(1))
            block_lines = block.splitlines()
            _apply_rules(block, block_lines, block_start_line, {"code"}, rel_path, findings)


def _parse_frontmatter(skill_md_path):
    """Extract name/description from a SKILL.md YAML frontmatter block, without a YAML dependency."""
    has_fm, desc = False, ""
    try:
        with open(skill_md_path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return has_fm, desc

    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not m:
        return has_fm, desc
    has_fm = True
    fm = m.group(1)
    dm = re.search(r"^description:\s*(.+)$", fm, re.MULTILINE)
    if dm:
        desc = dm.group(1).strip()
    return has_fm, desc


def _extract_declared_domains(skill_md_path):
    """Parse domains a skill declares in SKILL.md (network section or frontmatter)."""
    domains = set()
    try:
        with open(skill_md_path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return domains

    section = text
    section_match = re.search(
        r"^##[^\n]*network[^\n]*\n(.*?)(?=^##|\Z)",
        text,
        re.MULTILINE | re.IGNORECASE | re.DOTALL,
    )
    if section_match:
        section = section_match.group(1)

    for pattern in (DOMAIN_DECL_RE, BACKTICK_DOMAIN_RE):
        for match in pattern.finditer(section):
            domains.add(match.group(1).lower().rstrip("."))

    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        list_match = re.search(r"^allowed_domains:\s*\[(.*?)\]", fm, re.MULTILINE)
        if list_match:
            for domain in re.findall(r"[`'\"]?([a-z0-9.-]+\.[a-z]{2,})[`'\"]?", list_match.group(1)):
                domains.add(domain.lower())

    return domains


def _normalize_domains(domains):
    return sorted({d.lower().strip().rstrip(".") for d in domains if d.strip()})


def _is_allowlisted(finding, allowed_domains):
    if finding.rule_id not in NETWORK_ALLOWLIST_RULES or not allowed_domains:
        return False
    haystack = f"{finding.snippet}\n{finding.context}".lower()
    return any(domain in haystack for domain in allowed_domains)


def _filter_allowlisted(findings, allowed_domains):
    if not allowed_domains:
        return findings
    return [f for f in findings if not _is_allowlisted(f, allowed_domains)]


def _hash_directory(dir_path):
    """Stable content hash across all files in the skill — useful for detecting
    silent tampering between two scans of 'the same' skill."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(dir_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as fh:
                    h.update(fh.read())
            except OSError:
                continue
    return h.hexdigest()


def scan_skill(skill_dir, extra_allow_domains=None):
    """Scan a single skill directory (expected to contain a SKILL.md)."""
    name = os.path.basename(os.path.normpath(skill_dir))
    report = SkillReport(name=name, path=skill_dir)

    skill_md = os.path.join(skill_dir, "SKILL.md")
    allowed_domains = set(_normalize_domains(extra_allow_domains or []))
    if os.path.isfile(skill_md):
        report.has_frontmatter, report.declared_description = _parse_frontmatter(skill_md)
        allowed_domains.update(_extract_declared_domains(skill_md))
    report.allowed_domains = _normalize_domains(allowed_domains)

    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, skill_dir)
            if _file_type(fpath) is not None:
                report.files_scanned += 1
                _scan_file(fpath, rel, report.findings)

    report.findings = _filter_allowlisted(report.findings, report.allowed_domains)
    report.sha256 = _hash_directory(skill_dir)
    return report


def discover_skills(root_dir):
    """Find every subdirectory that looks like a skill (contains SKILL.md).
    Falls back to treating root_dir itself as a single skill if it directly
    contains a SKILL.md."""
    root_dir = os.path.abspath(root_dir)
    if os.path.isfile(os.path.join(root_dir, "SKILL.md")):
        return [root_dir]

    found = []
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if "SKILL.md" in files:
            found.append(root)
            dirs[:] = []  # don't descend into a skill's own subdirectories looking for nested skills
    return sorted(found)


def scan_all(root_dir, extra_allow_domains=None):
    return [scan_skill(d, extra_allow_domains=extra_allow_domains) for d in discover_skills(root_dir)]
