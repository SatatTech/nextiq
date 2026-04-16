# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document

# Fields written only by submit_card_scan() or scan_callback() via db.set_value.
# Any attempt to change them through a normal form save is rejected.
_SERVICE_FIELDS = (
	"status", "submitted_at", "processed_at", "merged_image",
	"lead", "scans_remaining", "error_message", "ai_response",
	"job_id", "cb_secret",
)


class CardScanLog(Document):
	def validate(self):
		if self.is_new():
			return  # allow insert — submit_card_scan creates the initial record

		# For existing docs: reload the stored values and reset any field
		# that the caller tried to change. This is defense-in-depth — the
		# read_only JSON flag and the JS client already block form edits;
		# this catches crafted API calls that bypass those layers.
		stored = frappe.db.get_value(
			"Card Scan Log", self.name,
			list(_SERVICE_FIELDS),
			as_dict=True,
		)
		if not stored:
			return

		changed = [f for f in _SERVICE_FIELDS if self.get(f) != stored.get(f)]
		if changed:
			frappe.log_error(
				f"User '{frappe.session.user}' attempted to modify protected fields "
				f"on Card Scan Log {self.name}: {', '.join(changed)}",
				"NextIQ: Unauthorized Field Edit Attempt",
			)
			frappe.throw(
				"Card Scan Log fields cannot be edited manually: "
				+ ", ".join(changed),
				title="Not Allowed",
			)
