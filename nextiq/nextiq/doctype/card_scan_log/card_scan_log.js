// Copyright (c) 2026, krushang.patel@satat.tech and contributors
// For license information, please see license.txt

// All fields on Card Scan Log are system-managed — filled only by
// submit_card_scan() or scan_callback(). No manual editing is allowed.
const READONLY_FIELDS = [
	"status",
	"submitted_at",
	"processed_at",
	"merged_image",
	"voice_audio",
	"voice_audio_2",
	"voice_audio_3",
	"voice_language",
	"lead",
	"scans_remaining",
	"error_message",
	"ai_response",
	"job_id",
	"cb_secret",
];

frappe.ui.form.on("Card Scan Log", {
	refresh(frm) {
		READONLY_FIELDS.forEach((f) => frm.set_df_property(f, "read_only", 1));
		frm.disable_save();
	},
});
