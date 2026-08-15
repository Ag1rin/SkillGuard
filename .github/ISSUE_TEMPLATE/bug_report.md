---
name: Bug report
about: Report something that isn't working as expected
title: "[BUG] "
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run `skillguard scan ...` with '...'
2. Given this SKILL.md / directory structure: '...'
3. See error / incorrect output

If possible, attach a minimal `SKILL.md` (or a snippet) that reproduces the issue — this is the fastest way to get it fixed.

**Expected behavior**
A clear and concise description of what you expected to happen (e.g. "should be flagged BLOCKED but was SAFE", "should not have flagged this as a finding").

**Actual output**
```
paste the actual terminal / JSON / Markdown output here
```

**Environment (please complete the following information):**
 - OS: [e.g. Ubuntu 22.04, macOS 14, Windows 11]
 - Python version: [e.g. 3.11.4] (`python --version`)
 - SkillGuard version: [e.g. 0.1.0] (`pip show skillguard` or the commit hash if run from source)
 - Installed via: [pip / cloned from source]

**Additional context**
Add any other context about the problem here — e.g. whether this is a false positive, false negative, a crash, or a formatting issue.
