no_cache = 1

import frappe


def get_context(context):
	if frappe.session.user == "Guest":
		frappe.local.flags.redirect_location = "/login?redirect-to=/card-scan"
		raise frappe.Redirect

	context.no_breadcrumbs = True
	context.no_sidebar = True
