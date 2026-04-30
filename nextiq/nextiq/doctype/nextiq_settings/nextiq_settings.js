frappe.ui.form.on("NextIQ Settings", {
	refresh(frm) {
		frm.add_custom_button(__("Check Updates"), function () {
			frappe.show_alert({ message: __("Checking version status…"), indicator: "blue" });
			frappe.call({
				method: "nextiq.version_check.check_service_version",
				callback(r) {
					if (r.exc) {
						frappe.show_alert({ message: __("Version check failed. Check the Error Log."), indicator: "red" });
						return;
					}
					if (!r.message) {
						frappe.show_alert({ message: __("Version check failed. Verify your API key."), indicator: "red" });
						return;
					}
					frm.reload_doc();
					frappe.show_alert({ message: __("Version status updated."), indicator: "green" });
					frappe.boot.nextiq_update = r.message;
					frappe._nextiq_notifications_shown = false;
					nextiq.show_update_notifications();
				},
			});
		}, __("Actions"));
	},
});
