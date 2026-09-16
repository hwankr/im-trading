"""Validate public paper-trading records without printing matching secrets."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKED_KEYS = {
    "account_number", "account_no", "bank_account", "real_name",
    "password", "api_key", "access_token", "refresh_token", "client_secret",
}
PATTERNS = {
    "local_user_path": re.compile(r"(?i)\b[A-Z]:[/\\]|/Users/|/home/"),
    "account_number": re.compile(r"(?<!\d)\d{4}[- ]\d{4}[- ]\d{2}(?!\d)"),
    "credential": re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    "local_attachment_embed": re.compile(r"!\[[^\]]*\]\([^)]*(?:\.codex-remote-attachments|file://)", re.I),
}


def inspect_object(value, location, errors):
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{location}.{key}"
            if key.lower() in BLOCKED_KEYS and item not in (None, "", [], {}):
                errors.append(f"{child}: identifying or credential field")
            inspect_object(item, child, errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            inspect_object(item, f"{location}[{index}]", errors)


def main():
    errors = []
    files = sorted(p for p in (ROOT / "data").rglob("*") if p.is_file())
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix not in {".json", ".md"}:
            errors.append(f"{relative}: unsupported public record type")
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{relative}: {label}")
        if path.suffix == ".json":
            try:
                inspect_object(json.loads(text), relative, errors)
            except json.JSONDecodeError as exc:
                errors.append(f"{relative}: invalid JSON at line {exc.lineno}")
    if errors:
        print("Public record check failed:\n" + "\n".join(errors))
        return 1
    print(f"Public record check passed: {len(files)} files. Manual review is still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
