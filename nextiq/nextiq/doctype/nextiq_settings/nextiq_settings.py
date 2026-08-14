# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import frappe
from frappe import _
from frappe.model.document import Document


class NextIQSettings(Document):
	def validate(self):
		self.validate_lead_destination()

	def validate_lead_destination(self):
		"""
		lead_destination's option list is filtered client-side (see
		nextiq_settings.js) to only apps installed on this site, but that
		filtering never runs for API/console/data-import writes — enforce it
		here too so an app that isn't installed can never be selected as (or
		left as, if it was installed and then removed) the destination.
		"""
		installed = frappe.get_installed_apps()
		requires_erpnext = self.lead_destination in ("ERPNext", "Both")
		requires_crm = self.lead_destination in ("Frappe CRM", "Both")

		if requires_erpnext and "erpnext" not in installed:
			frappe.throw(
				_("Lead Destination is set to {0}, but ERPNext is not installed on this site.").format(
					self.lead_destination
				)
			)
		if requires_crm and "crm" not in installed:
			frappe.throw(
				_("Lead Destination is set to {0}, but Frappe CRM is not installed on this site.").format(
					self.lead_destination
				)
			)
