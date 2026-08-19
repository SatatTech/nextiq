# Run via: bench --site <site> execute ensure_default_records.ensure_transit_warehouse_type
# (with .github/ci/ on PYTHONPATH — see ci.yml)
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
import frappe


def ensure_transit_warehouse_type():
	if not frappe.db.exists("Warehouse Type", "Transit"):
		frappe.get_doc({"doctype": "Warehouse Type", "name": "Transit"}).insert(ignore_permissions=True)
		frappe.db.commit()
