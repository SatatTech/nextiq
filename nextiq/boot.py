import nextiq
import frappe

from nextiq.version_check import _version_lt


def boot_session(bootinfo):
	"""Inject NextIQ version status into the boot payload for the desk banner."""
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
