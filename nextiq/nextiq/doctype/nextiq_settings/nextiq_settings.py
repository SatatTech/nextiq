# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class NextIQSettings(Document):
	def on_update(self):
		# Mark setup complete whenever api_key is saved (wizard or manual paste)
		if self.api_key and not self.setup_complete:
			frappe.db.set_single_value("NextIQ Settings", "setup_complete", 1)
