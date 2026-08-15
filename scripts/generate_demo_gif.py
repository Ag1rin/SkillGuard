"""Generate the README terminal demo GIF for SkillGuard."""

from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "demo.gif"

WIDTH, HEIGHT = 860, 500
BG = (13, 17, 23)
FG = (230, 237, 243)
DIM = (139, 148, 158)
RED = (248, 81, 73)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)
BORDER = (48, 54, 61)

FONT_CANDIDATES = [
    "C:/Windows/Fonts/consola.ttf",
    "C:/Windows/Fonts/CascadiaMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]

FONT_SIZE = 15
LINE_HEIGHT = 21
PADDING = 22
COMMAND = "skillguard scan examples"

OUTPUT_LINES = [
    ("title", "SkillGuard - Skill Security Scan", FG),
    ("dim", "Scanned 6 skill(s) * 2026-08-15 17:48 UTC", DIM),
    ("blank", "", FG),
    ("blocked", "[X] BLOCKED  malicious-skill  (score 95)", RED),
    ("finding", "    PI001  Ignore all previous instructions...", YELLOW),
    ("finding", "    EX003  References webhook.site exfiltration", YELLOW),
    ("blank", "", FG),
    ("blocked", "[X] BLOCKED  malicious-skill-hooks  (score 59)", RED),
    ("finding", "    HK001  Agent lifecycle hook (PostToolUse)", YELLOW),
    ("blank", "", FG),
    ("blocked", "[X] BLOCKED  malicious-skill-mcp-creds  (score 30)", RED),
    ("finding", "    SC003  Hardcoded apiKey in .mcp.json", YELLOW),
    ("blank", "", FG),
    ("safe", "[+] SAFE     safe-skill  (score 0)", GREEN),
    ("safe", "[+] SAFE     review-skill-webhook-integration", GREEN),
    ("blank", "", FG),
    ("title", "Summary", FG),
    ("summary", "  SAFE: 2   REVIEW: 0   BLOCKED: 4", FG),
]


def load_font() -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONT_CANDIDATES:
        if os.path.isfile(path):
            return ImageFont.truetype(path, FONT_SIZE)
    return ImageFont.load_default()


def text_width(draw: ImageDraw.ImageDraw, text: str, font) -> float:
    if hasattr(draw, "textlength"):
        return draw.textlength(text, font=font)
    return font.getlength(text)


def render_frame(visible_lines, command_visible: str = "", show_cursor: bool = False) -> Image.Image:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    font = load_font()

    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        x = PADDING + i * 20
        draw.ellipse((x, 10, x + 10, 20), fill=color)

    y = 38
    prompt = "$ "
    draw.text((PADDING, y), prompt + command_visible, fill=FG, font=font)
    if show_cursor:
        cx = PADDING + text_width(draw, prompt + command_visible, font)
        draw.rectangle((cx, y + 1, cx + 7, y + LINE_HEIGHT - 5), fill=FG)
    y += LINE_HEIGHT + 10

    for kind, text, color in visible_lines:
        if kind == "blank":
            y += LINE_HEIGHT // 2
            continue
        draw.text((PADDING, y), text, fill=color, font=font)
        y += LINE_HEIGHT

    draw.rounded_rectangle((0, 0, WIDTH - 1, HEIGHT - 1), radius=10, outline=BORDER, width=2)
    return img


def main() -> None:
    frames: list[tuple[Image.Image, int]] = []

    for i in range(len(COMMAND) + 1):
        frames.append((render_frame([], COMMAND[:i], True), 70))
    frames.append((render_frame([], COMMAND, False), 350))

    for i in range(1, len(OUTPUT_LINES) + 1):
        frames.append((render_frame(OUTPUT_LINES[:i], COMMAND, False), 110))

    final = render_frame(OUTPUT_LINES, COMMAND, False)
    for _ in range(12):
        frames.append((final, 120))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    images = [frame for frame, _ in frames]
    durations = [duration for _, duration in frames]
    images[0].save(
        OUT,
        save_all=True,
        append_images=images[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    size_kb = OUT.stat().st_size / 1024
    print(f"Wrote {OUT} ({len(images)} frames, {size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
