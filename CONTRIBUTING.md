# Contributing to SkillGuard

Thanks for considering it. This project stays useful only if its rules stay sharp and its false-positive rate stays low — both need real-world input.

## Adding a detection rule

1. Open `skillguard/patterns.py`.
2. Add a `Rule(...)` with:
   - a new unique `id` (prefix by category: `PI` prompt injection, `CE` code execution, `EX` exfiltration, `FS` filesystem, `OB` obfuscation, `SC` supply chain)
   - the smallest regex that reliably catches the pattern — prefer specific over clever
   - a severity that matches real-world impact, not worst-case paranoia
   - a one-line `description` a non-expert can understand
3. Add a test case in `tests/test_analyzer.py`, ideally by extending `examples/malicious-skill/SKILL.md` (or adding a new example) so CI proves the rule fires.
4. If you're fixing a false positive, add a test proving the *safe* case no longer triggers, alongside the existing test that the *unsafe* case still does.

## Reporting a real-world malicious skill you found

Please don't paste the full malicious content into a public issue if it contains a working exploit or a live exfiltration endpoint — sanitize it first (defang URLs, redact tokens) or email the maintainers privately. Do include:
- what the skill claimed to do vs. what it actually did
- which of our rules did/didn't catch it

## Development setup

```bash
git clone https://github.com/Ag1rin/SkillGuard.git
cd skillguard
python -m unittest discover -s tests -v
python -m skillguard.cli scan examples
```

No dependencies to install — the project intentionally uses only the Python standard library so it's trivial to audit and trivial to run anywhere.

## Code style

Keep it boring and readable. This is a security tool; clever code is a liability here. Favor explicit regexes and short functions over abstraction.
