import frappe


def get_context(context):
	# Only System Managers may access this page
	if frappe.session.user == "Guest":
		frappe.local.flags.redirect_location = "/login?redirect-to=/nextiq-setup"
		raise frappe.Redirect

	if "System Manager" not in frappe.get_roles(frappe.session.user):
		frappe.throw("Not permitted.", frappe.PermissionError)

	# Already set up — send back to desk
	settings = frappe.db.get_singles_dict("NextIQ Settings")
	if int(settings.get("setup_complete") or 0) or settings.get("api_key"):
		frappe.local.flags.redirect_location = "/app"
		raise frappe.Redirect

	context.no_cache  = 1
	context.no_header = 1
	context.no_footer = 1
