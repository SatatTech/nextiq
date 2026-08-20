# Run via: python3 .github/ci/compute_frappe_matrix.py >> "$GITHUB_OUTPUT"
# (from the repo root — see ci.yml's "prepare" job)
#
# Derives ci.yml's Frappe version-branch test matrix from pyproject.toml's
# own [tool.bench.frappe-dependencies] range, rather than hardcoding a
# second, driftable copy of it in the workflow file. pyproject.toml stays
# the single source of truth for what nextiq claims to support — and now
# also for what CI actually verifies, so the two can't quietly disagree.
#
# ">=15.0.0,<17.0.0" -> ["version-15", "version-16"]
import json
import re
import sys

import tomllib

with open("pyproject.toml", "rb") as f:
	data = tomllib.load(f)

constraint = data["tool"]["bench"]["frappe-dependencies"]["frappe"]
match = re.match(r"^>=(\d+)\.\d+\.\d+,<(\d+)\.\d+\.\d+$", constraint)
if not match:
	sys.exit(f"Could not parse frappe-dependencies constraint: {constraint!r}")

low, high = int(match.group(1)), int(match.group(2))
versions = [f"version-{v}" for v in range(low, high)]
print(f"versions={json.dumps(versions)}")
