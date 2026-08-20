# Run via: env/bin/python .github/ci/ensure_default_records.py test_site
# (from the bench root, so the site name resolves under sites/) — see ci.yml
#
# CI-only test-environment setup, not part of nextiq itself: Frappe's test
# runner auto-creates a test Company record for any app under test once
# erpnext is installed, which cascades into Company.create_default_warehouses()
# needing "Warehouse Type: Transit" to already exist. erpnext's own
# after_install hook (install_fixtures.py) is supposed to create it, but on
# some version-15 point releases it doesn't — a known upstream bug
# (frappe/erpnext#42309, #43261, #43262, #28928), unrelated to nextiq.
# This just fills that one gap so the test harness can proceed. No-op if
# the record already exists (e.g. on version-16, where it's fine).
#
# Plain script rather than `bench execute`: that command resolves dotted
# paths through frappe.get_attr(), which requires the first segment to be
# a real *installed app name*, not just an importable module on
# PYTHONPATH — it isn't a generic Python import, so a standalone CI script
# can never be reached that way regardless of PYTHONPATH.
import sys

import frappe

site = sys.argv[1]
frappe.init(site=site)
frappe.connect()
if not frappe.db.exists("Warehouse Type", "Transit"):
	frappe.get_doc({"doctype": "Warehouse Type", "name": "Transit"}).insert(ignore_permissions=True)
	# Standalone CI script, outside any request/transaction context.
	frappe.db.commit()  # nosemgrep
frappe.destroy()
