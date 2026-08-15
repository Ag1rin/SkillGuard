"""
patterns.py — Detection rules for SkillGuard.

Every rule has:
  - id:        stable identifier (used in reports / suppressions)
  - category:  PROMPT_INJECTION | CODE_EXECUTION | EXFILTRATION | FILESYSTEM |
               OBFUSCATION | SUPPLY_CHAIN | METADATA
  - severity:  LOW (1) | MEDIUM (3) | HIGH (7) | CRITICAL (15)
  - pattern:   compiled regex
  - file_types: which files this rule applies to ('md', 'code', 'all')
  - description: human explanation shown in the report

Scoring is intentionally simple and transparent: sum of triggered severities.
See analyzer.py for how the final verdict is derived.
"""

import re

LOW, MEDIUM, HIGH, CRITICAL = 1, 3, 7, 15


class Rule:
    __slots__ = ("id", "category", "severity", "pattern", "file_types", "description")

    def __init__(self, id, category, severity, pattern, file_types, description):
        self.id = id
        self.category = category
        self.severity = severity
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.file_types = file_types
        self.description = description


RULES = [

    # ---------------------------------------------------------------
    # PROMPT INJECTION — instructions aimed at the *agent*, not the user
    # ---------------------------------------------------------------
    Rule(
        "PI001", "PROMPT_INJECTION", CRITICAL,
        r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)\b",
        "all",
        "Attempts to override prior instructions — classic prompt-injection phrasing.",
    ),
    Rule(
        "PI002", "PROMPT_INJECTION", CRITICAL,
        r"\b(do\s+not|don't|never)\s+(tell|inform|mention|show|reveal)\s+(the\s+)?(user|human|person)\b",
        "all",
        "Instructs the agent to hide actions or information from the user.",
    ),
    Rule(
        "PI003", "PROMPT_INJECTION", HIGH,
        r"\byou\s+are\s+now\s+(a|an|in)\b|\bnew\s+system\s+prompt\b|\bsystem\s*:\s*override\b",
        "all",
        "Tries to redefine the agent's identity or system prompt mid-skill.",
    ),
    Rule(
        "PI004", "PROMPT_INJECTION", HIGH,
        r"\b(always|silently)\s+(run|execute|send|forward|upload|email)\b",
        "all",
        "Instructs unconditional, silent action — a common exfiltration setup.",
    ),
    Rule(
        "PI005", "PROMPT_INJECTION", MEDIUM,
        r"\bbefore\s+(responding|answering|replying)\s*,?\s*(first\s+)?(send|post|fetch|upload)\b",
        "all",
        "Chains a hidden network action before the visible response.",
    ),
    Rule(
        "PI006", "PROMPT_INJECTION", HIGH,
        r"\bjailbreak\b|\bDAN\s+mode\b|\bdeveloper\s+mode\s+enabled\b|\bunlock\s+(all\s+)?restrictions\b",
        "all",
        "Language associated with attempts to bypass model safety behavior.",
    ),
    Rule(
        "PI007", "PROMPT_INJECTION", MEDIUM,
        r"\bact\s+as\s+if\s+you\s+(have|had)\s+no\s+(restrictions|guidelines|limits)\b",
        "all",
        "Attempts to convince the agent it is unconstrained.",
    ),

    # ---------------------------------------------------------------
    # HIDDEN / INVISIBLE CONTENT
    # ---------------------------------------------------------------
    Rule(
        "OB001", "OBFUSCATION", CRITICAL,
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        "all",
        "Zero-width or invisible Unicode characters — often used to hide injected text from human reviewers.",
    ),
    Rule(
        "OB002", "OBFUSCATION", HIGH,
        r"<!--.*?(ignore|system|override|instructions?).*?-->",
        "md",
        "Instructions hidden inside an HTML comment (invisible when rendered).",
    ),
    Rule(
        "OB003", "OBFUSCATION", MEDIUM,
        r"[A-Za-z0-9+/]{200,}={0,2}",
        "all",
        "Long base64-like blob — could be obfuscated payload or legitimate binary data; review recommended.",
    ),

    # ---------------------------------------------------------------
    # CODE EXECUTION RISK (in .py / .sh / .js companion scripts)
    # ---------------------------------------------------------------
    Rule(
        "CE001", "CODE_EXECUTION", CRITICAL,
        r"\bos\.system\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True",
        "code",
        "Shell execution with unsanitized input risk (os.system / shell=True).",
    ),
    Rule(
        "CE002", "CODE_EXECUTION", HIGH,
        r"\beval\s*\(|\bexec\s*\(",
        "code",
        "Dynamic code execution (eval/exec) — hard to audit statically.",
    ),
    Rule(
        "CE003", "CODE_EXECUTION", CRITICAL,
        r"curl\s+[^|]*\|\s*(sudo\s+)?(bash|sh)\b|wget\s+[^|]*\|\s*(sudo\s+)?(bash|sh)\b",
        "code",
        "Pipes a remote download directly into a shell interpreter (curl|bash pattern).",
    ),
    Rule(
        "CE004", "CODE_EXECUTION", MEDIUM,
        r"\b__import__\s*\(|\bimportlib\.import_module\s*\(",
        "code",
        "Dynamic import — legitimate at times, but can load unexpected modules.",
    ),

    # ---------------------------------------------------------------
    # EXFILTRATION — sending data somewhere
    # ---------------------------------------------------------------
    Rule(
        "EX001", "EXFILTRATION", HIGH,
        r"\brequests\.(post|put)\s*\(|\bfetch\s*\(\s*['\"]https?://(?!localhost)",
        "code",
        "Outbound HTTP call — verify the destination is expected and declared.",
    ),
    Rule(
        "EX002", "EXFILTRATION", CRITICAL,
        r"\bos\.environ\b.*\b(requests|fetch|urlopen|post)\b|\b(requests|fetch|urlopen)\b.*\bos\.environ\b",
        "code",
        "Environment variables appear near a network call — possible secret exfiltration.",
    ),
    Rule(
        "EX003", "EXFILTRATION", HIGH,
        r"webhook\.site|ngrok\.io|requestbin|pipedream\.net",
        "all",
        "References a throwaway webhook/tunnel service commonly used to exfiltrate data during testing or attacks.",
    ),
    Rule(
        "EX004", "EXFILTRATION", MEDIUM,
        r"\bsmtplib\b|\bsendmail\b",
        "code",
        "Sends email from within a skill — confirm this is an expected feature.",
    ),

    # ---------------------------------------------------------------
    # FILESYSTEM — reaching outside the skill's own scope
    # ---------------------------------------------------------------
    Rule(
        "FS001", "FILESYSTEM", CRITICAL,
        r"\.ssh/id_rsa|\.ssh/id_ed25519|\.aws/credentials|\.netrc\b|\.npmrc\b.*token",
        "all",
        "References a well-known secrets file location (SSH keys, AWS creds, npm token).",
    ),
    Rule(
        "FS002", "FILESYSTEM", HIGH,
        r"open\s*\(\s*['\"]~?/(etc/passwd|etc/shadow)",
        "code",
        "Attempts to read sensitive system files.",
    ),
    Rule(
        "FS003", "FILESYSTEM", MEDIUM,
        r"\bos\.path\.expanduser\s*\(\s*['\"]~['\"]\s*\)|\bPath\.home\s*\(\s*\)",
        "code",
        "Reaches into the user's home directory — confirm scope is necessary and declared.",
    ),
    Rule(
        "FS004", "FILESYSTEM", HIGH,
        r"\.env\b(?!\.example|\.sample)",
        "all",
        "References a .env file, which commonly holds secrets.",
    ),

    # ---------------------------------------------------------------
    # SUPPLY CHAIN — installing/fetching more code at runtime
    # ---------------------------------------------------------------
    Rule(
        "SC001", "SUPPLY_CHAIN", HIGH,
        r"\bpip\s+install\b(?!.*--break-system-packages).{0,80}\bgit\+https?://",
        "all",
        "Installs a package directly from a git URL rather than a pinned registry release.",
    ),
    Rule(
        "SC002", "SUPPLY_CHAIN", MEDIUM,
        r"\bnpm\s+install\s+.*(github:|http)",
        "all",
        "Installs an npm package from an arbitrary URL instead of the registry.",
    ),
    Rule(
        "SC003", "SUPPLY_CHAIN", CRITICAL,
        r"[\"']?(api[_-]?key|token|secret)[\"']?\s*:\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        "all",
        "Hardcoded credential in a config file (e.g. .mcp.json) — pre-wires the installer's "
        "agent to a server or account the attacker controls. Documented in real skill-supply-chain "
        "compromises, e.g. hardcoded API keys shipped inside a bundled .mcp.json.",
    ),

    # ---------------------------------------------------------------
    # HOOK / LIFECYCLE ABUSE — Claude Code and similar agents support
    # pre/post tool-use hooks and session-lifecycle hooks. Real-world
    # malicious skills have weaponized these to run unattended.
    # ---------------------------------------------------------------
    Rule(
        "HK001", "EXFILTRATION", CRITICAL,
        r"\b(PreToolUse|PostToolUse|SessionEnd|SessionStart|on_tool_(use|complete)|session[_-]end)\b",
        "all",
        "References an agent lifecycle hook (fires on every tool call or session end). Documented "
        "in the wild as a way to silently monitor or exfiltrate agent activity without the user "
        "seeing it in the visible conversation.",
    ),
    Rule(
        "HK002", "PROMPT_INJECTION", HIGH,
        r"\bonly\s+(when|if)\s+the\s+user\s+(says|types|mentions)\s+[\"'][^\"']{2,40}[\"']\s*,?\s*(then\s+)?(silently|secretly)\b",
        "all",
        "A conditional 'trigger phrase' that activates hidden behavior — the 'sleeper' pattern "
        "documented in recent skill-supply-chain research, where malicious code stays dormant "
        "until a specific codeword appears.",
    ),

    # ---------------------------------------------------------------
    # URL-BASED EXFILTRATION — smuggling captured data out via a link
    # or query string that the agent is told to surface to the user.
    # ---------------------------------------------------------------
    Rule(
        "EX005", "EXFILTRATION", CRITICAL,
        r"https?://[^\s\"'()]*[?&][A-Za-z0-9_]{1,20}=\s*[\"']?\s*\+|https?://[^\s\"'()]*\$\([^)]+\)|https?://[^\s\"'()]*\{[^}]{1,40}\}",
        "all",
        "A URL is built by concatenating or interpolating a variable into it — a documented "
        "technique for smuggling captured data (passwords, tokens) out through a link the model "
        "is induced to surface to the user, who then clicks it.",
    ),
    Rule(
        "EX006", "EXFILTRATION", HIGH,
        r"\b(env\s*\|\s*base64|os\.environ.{0,20}b64encode|base64\.b64encode\s*\(\s*(str\s*\()?os\.environ)",
        "code",
        "Base64-encodes environment variables — a common step right before exfiltrating secrets "
        "through a URL, header, or log line.",
    ),

    # ---------------------------------------------------------------
    # CROSS-FILE INSTRUCTION CHAINING — a skill instructing the agent to
    # go read/execute an unrelated config file, documented as a real
    # exploit chain (skill has Bash access -> tells agent to `source`
    # an .env/.cursorrules/config file it wouldn't otherwise touch).
    # ---------------------------------------------------------------
    Rule(
        "PI008", "PROMPT_INJECTION", HIGH,
        r"\b(source|cat|read|load)\s+(the\s+)?(project'?s?\s+)?\.?(env|cursorrules|npmrc|netrc)\b",
        "all",
        "Instructs the agent to read or source a file that commonly holds secrets or hidden "
        "instructions, as part of an otherwise-unrelated task — a documented exploit chain "
        "for skills with legitimate-looking Bash/Read access.",
    ),
]


NETWORK_ALLOWLIST_HINT = (
    "Tip: skills that need the network should document every destination domain "
    "explicitly in SKILL.md so reviewers can allowlist rather than guess."
)
