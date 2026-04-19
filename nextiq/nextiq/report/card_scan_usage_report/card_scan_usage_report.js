// Copyright (c) 2026, krushang.patel@satat.tech and contributors
// For license information, please see license.txt

frappe.query_reports["Card Scan Usage Report"] = {
	filters: [
		{
			fieldname: "from_date",
			label: __("From Date"),
			fieldtype: "Date",
			default: frappe.datetime.add_months(frappe.datetime.get_today(), -1),
			reqd: 1,
		},
		{
			fieldname: "to_date",
			label: __("To Date"),
			fieldtype: "Date",
			default: frappe.datetime.get_today(),
			reqd: 1,
		},
	],

	onload(report) {
		report.page.add_inner_button(__("Live Balance"), () => {
			frappe.call({
				method: "nextiq.api.get_live_balance",
				freeze: true,
				freeze_message: __("Fetching live balance from service..."),
				callback(r) {
					const d = r.message;
					if (!d || !d.success) {
						frappe.msgprint({
							title: __("Balance Check Failed"),
							message: d?.message || __("Could not fetch balance from service."),
							indicator: "red",
						});
						return;
					}
					const pct = d.scans_allowed
						? ((d.scans_used / d.scans_allowed) * 100).toFixed(1)
						: 0;
					const indicator = d.scans_remaining === 0 ? "red"
						: d.scans_remaining < d.scans_allowed * 0.2 ? "orange"
						: "green";
					frappe.msgprint({
						title: __("Live Scan Balance"),
						indicator,
						message: `
							<table class="table table-bordered table-sm" style="margin-top:8px">
								<tr><th>${__("Total Allocated")}</th><td><strong>${d.scans_allowed}</strong></td></tr>
								<tr><th>${__("Scans Used")}</th><td>${d.scans_used} (${pct}%)</td></tr>
								<tr class="${indicator === 'green' ? 'table-success' : indicator === 'orange' ? 'table-warning' : 'table-danger'}">
									<th>${__("Remaining Balance")}</th>
									<td><strong>${d.scans_remaining}</strong></td>
								</tr>
								<tr><th>${__("Account Status")}</th><td>${d.status}</td></tr>
							</table>
						`,
					});
				},
			});
		});
	},
};
