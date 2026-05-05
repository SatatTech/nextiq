frappe.ui.form.on("NextIQ Settings", {
	refresh(frm) {
		// Filter lead_destination options to only apps that are installed
		frappe.call({
			method: "nextiq.api.get_installed_lead_destinations",
			callback(r) {
				if (!r.message) return;
				const { has_erpnext, has_crm } = r.message;
				let options = [];
				if (has_erpnext) options.push("ERPNext");
				if (has_crm)     options.push("Frappe CRM");
				if (has_erpnext && has_crm) options.push("Both");
				frm.set_df_property("lead_destination", "options", options.join("\n"));
				if (options.length && !options.includes(frm.doc.lead_destination)) {
					frm.set_value("lead_destination", options[0]);
				}
			},
		});

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
