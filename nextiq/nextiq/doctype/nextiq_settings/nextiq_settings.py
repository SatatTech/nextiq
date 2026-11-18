# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


def get_default_lead_destination():
	"""Best destination for this site: ERPNext if installed (backward compatible),
	otherwise Frappe CRM, otherwise None."""
	installed = frappe.get_installed_apps()
	if "erpnext" in installed:
		return "ERPNext"
	if "crm" in installed:
		return "Frappe CRM"
	return None


class NextIQSettings(Document):
	def validate(self):
		self.validate_lead_destination()

	def validate_lead_destination(self):
		"""
		lead_destination's option list is filtered client-side (see
		nextiq_settings.js) to only apps installed on this site, but that
		filtering never runs for API/console/data-import writes — enforce it
		here too.

		A destination the user *just chose* that isn't installed is rejected.
		A blank or stale value (e.g. the app was uninstalled later, or the
		setting was never touched) is silently replaced by what is available,
		so unrelated saves such as the OAuth connect flow never fail on it.
		"""
		installed = frappe.get_installed_apps()
		requires_erpnext = self.lead_destination in ("ERPNext", "Both")
		requires_crm = self.lead_destination in ("Frappe CRM", "Both")
		invalid = (requires_erpnext and "erpnext" not in installed) or (
			requires_crm and "crm" not in installed
		)

		if self.lead_destination and not invalid:
			return

		if self.lead_destination and self.has_value_changed("lead_destination"):
			missing = "ERPNext" if requires_erpnext and "erpnext" not in installed else "Frappe CRM"
			frappe.throw(
				_("Lead Destination is set to {0}, but {1} is not installed on this site.").format(
					self.lead_destination, missing
				)
			)

		self.lead_destination = get_default_lead_destination()
