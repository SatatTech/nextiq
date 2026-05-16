import frappe


def execute():
	"""
	One-time patch: existing customers who already have an API key
	must not see the setup wizard after app update.
	"""
	api_key = frappe.db.get_single_value("NextIQ Settings", "api_key")
	if api_key:
		frappe.db.set_single_value("NextIQ Settings", "setup_complete", 1)
		frappe.db.commit()
