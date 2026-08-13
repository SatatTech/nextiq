import frappe


def execute():
	"""
	This site's nextiq app is being upgraded to the OAuth-capable version.
	If it was already working via the legacy API key (never went through the
	OAuth Connect flow), mark it Connected so NextIQ Settings reflects reality
	and the "Connect" button doesn't wrongly suggest nothing is set up.
	Real OAuth-connected sites (oauth_access_token already set) are untouched.
	"""
	settings = frappe.get_single("NextIQ Settings")
	if (
		settings.connection_status in (None, "Not Connected")
		and settings.api_key
		and not settings.oauth_access_token
	):
		frappe.db.set_single_value("NextIQ Settings", "connection_status", "Connected")
