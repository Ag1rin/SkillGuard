# Security Policy

## Reporting a Vulnerability

If you find a security issue **in SkillGuard itself** (not a malicious skill you scanned with it), please report it responsibly:

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Open a [private security advisory](https://github.com/Ag1rin/SkillGuard/security/advisories/new) on GitHub, or email the maintainers with:
   - a description of the issue
   - steps to reproduce
   - impact assessment, if known

We aim to acknowledge reports within **72 hours** and provide a fix or mitigation plan as quickly as practical.

## Scope

**In scope**

- Bugs in SkillGuard's CLI, scanner, or packaging that could lead to arbitrary code execution, path traversal, or similar issues on the machine running SkillGuard.

**Out of scope**

- Malicious skills found in the wild (report those via a regular issue — see [CONTRIBUTING.md](CONTRIBUTING.md), but sanitize live exfiltration endpoints first).
- False negatives in regex rules (those are expected limitations; please contribute improved rules instead).
- Security of third-party Skills you scan with SkillGuard.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |
