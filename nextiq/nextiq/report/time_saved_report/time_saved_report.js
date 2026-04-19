// Copyright (c) 2026, krushang.patel@satat.tech and contributors
// For license information, please see license.txt

frappe.query_reports["Time Saved Report"] = {
	filters: [
		{
			fieldname: "period",
			label: __("Period"),
			fieldtype: "Select",
			options: "Daily\nWeekly\nMonthly\nQuarterly\nYearly",
			default: "Daily",
			reqd: 1,
		},
		{
			fieldname: "from_date",
			label: __("From Date"),
			fieldtype: "Date",
		},
		{
			fieldname: "to_date",
			label: __("To Date"),
			fieldtype: "Date",
		},
	],
};
