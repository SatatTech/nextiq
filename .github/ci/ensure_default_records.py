# Run via: bench --site <site> console < .github/ci/ensure_default_records.py
#
# Known upstream ERPNext bug on version-15 (frappe/erpnext#42309, #43261,
# #43262, #28928): erpnext.setup.install.after_install is supposed to
# create "Warehouse Type: Transit" via install_fixtures(), but on some v15
# point releases it doesn't, and the first test Company record then fails
# with "Could not find Warehouse Type: Transit". Not a nextiq issue — this
# just fills the gap defensively before tests run. No-op if it already exists.
import frappe

if not frappe.db.exists("Warehouse Type", "Transit"):
	frappe.get_doc({"doctype": "Warehouse Type", "name": "Transit"}).insert(ignore_permissions=True)
	frappe.db.commit()
