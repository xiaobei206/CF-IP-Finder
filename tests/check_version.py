from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
source = (root / "cf_ip_finder.py").read_text(encoding="utf-8")
match = re.search(r'^APP_VERSION\s*=\s*[\'"]([^\'"]+)[\'"]', source, re.M)
if not match:
    raise SystemExit("APP_VERSION is missing")
if match.group(1) != version:
    raise SystemExit(f"VERSION={version}, APP_VERSION={match.group(1)}")
print(f"Version consistency OK: {version}")
