import nextiq
import frappe

from nextiq.version_check import _version_lt


def boot_session(bootinfo):
	"""Inject NextIQ version status and setup wizard flag into the boot payload."""
	try:
		service_min = frappe.db.get_value(
			"NextIQ Settings", "NextIQ Settings", "service_min_version"
		) or ""
		mandatory = bool(service_min and _version_lt(nextiq.__version__, service_min))
		bootinfo.nextiq_update = {
			"mandatory":       mandatory,
			"current_version": nextiq.__version__,
			"min_version":     service_min,
		}
	except Exception:
		bootinfo.nextiq_update = {}

	# Show setup wizard to System Managers on sites that have not yet connected
	try:
		if "System Manager" in frappe.get_roles(frappe.session.user):
			settings = frappe.db.get_singles_dict("NextIQ Settings")
			setup_needed = (
				not int(settings.get("setup_complete") or 0)
				and not settings.get("api_key")
			)
			bootinfo.nextiq_setup_needed = setup_needed
		else:
			bootinfo.nextiq_setup_needed = False
	except Exception:
		bootinfo.nextiq_setup_needed = False
