"""SkillGuard — static security scanner for AI agent Skills."""

__version__ = "0.2.0"

from .analyzer import scan_all, scan_skill, discover_skills, SkillReport, Finding  # noqa: F401
