no_cache = 1

import nextiq
import frappe

from nextiq.version_check import _version_lt, check_service_version


def get_context(context):
	if frappe.session.user == "Guest":
		frappe.local.flags.redirect_location = "/login?redirect-to=/card-scan"
		raise frappe.Redirect

	context.no_breadcrumbs = True
	context.no_sidebar = True

	_maybe_sync_version()

	service_min_version = frappe.db.get_value(
		"NextIQ Settings", "NextIQ Settings", "service_min_version"
	) or ""

	context.service_min_version    = service_min_version
	context.current_version        = nextiq.__version__
	context.needs_mandatory_update = bool(
		service_min_version and _version_lt(nextiq.__version__, service_min_version)
	)


def _maybe_sync_version():
	"""Sync min version from service, at most once every 5 minutes."""
	try:
		last_checked = frappe.db.get_value(
			"NextIQ Settings", "NextIQ Settings", "version_last_checked"
		)
		if last_checked:
			from frappe.utils import time_diff_in_seconds, now_datetime
			if time_diff_in_seconds(now_datetime(), last_checked) < 300:
				return
		check_service_version()
	except Exception:
		pass
