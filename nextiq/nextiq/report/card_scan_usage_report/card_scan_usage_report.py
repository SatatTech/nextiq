# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import frappe
from nextiq.api import get_live_balance

# Statuses where quota was consumed (AI ran, scan is billable)
CHARGED = {"Success", "Invalid Image", "Invalid Data", "Duplicate Lead"}
# Statuses where nothing was consumed
NOT_CHARGED = {"Failed", "Quota Exceeded"}
# In-flight — not yet terminal
IN_FLIGHT = {"Pending", "Processing"}

_STATUS_ORDER = [
	"Success",
	"Invalid Image",
	"Invalid Data",
	"Duplicate Lead",
	"Failed",
	"Quota Exceeded",
	"Pending",
	"Processing",
]

_STATUS_COLOR = {
	"Success":        "#2ecc71",
	"Invalid Image":  "#f39c12",
	"Invalid Data":   "#e67e22",
	"Duplicate Lead": "#3498db",
	"Failed":         "#e74c3c",
	"Quota Exceeded": "#95a5a6",
	"Pending":        "#bdc3c7",
	"Processing":     "#bdc3c7",
}


def execute(filters=None):
	filters = filters or {}
	from_date = filters.get("from_date")
	to_date   = filters.get("to_date")

	columns = [
		{"fieldname": "group",   "label": "Group",   "fieldtype": "Data", "width": 130},
		{"fieldname": "status",  "label": "Status",  "fieldtype": "Data", "width": 150},
		{"fieldname": "count",   "label": "Scans",   "fieldtype": "Int",  "width": 100},
		{"fieldname": "charged", "label": "Charged?", "fieldtype": "Data", "width": 100},
	]

	# ── Counts by status ──────────────────────────────────────────────────────
	rows = frappe.db.sql("""
		SELECT status, COUNT(*) AS count
		FROM `tabCard Scan Log`
		WHERE DATE(submitted_at) BETWEEN %(from_date)s AND %(to_date)s
		GROUP BY status
	""", {"from_date": from_date, "to_date": to_date}, as_dict=True)

	counts = {r.status: r.count for r in rows}

	# ── Live remaining balance from nextiq_service ────────────────────────────
	balance_source = None
	scans_remaining = scans_allowed_live = scans_used_live = None
	try:
		live = get_live_balance()
		if live and live.get("success"):
			scans_remaining    = live.get("scans_remaining")
			scans_allowed_live = live.get("scans_allowed")
			scans_used_live    = live.get("scans_used")
			balance_source     = "live"
	except Exception:
		pass

	# Fall back to last log record if live fetch failed
	if scans_remaining is None:
		latest = frappe.db.sql("""
			SELECT scans_remaining
			FROM `tabCard Scan Log`
			WHERE scans_remaining IS NOT NULL AND scans_remaining != 0
			ORDER BY processed_at DESC
			LIMIT 1
		""", as_dict=True)
		scans_remaining = latest[0].scans_remaining if latest else None
		balance_source  = "cached" if scans_remaining is not None else None

	# ── Build data rows ───────────────────────────────────────────────────────
	charged_total     = 0
	not_charged_total = 0
	data = []

	for status in _STATUS_ORDER:
		count = counts.get(status, 0)
		if not count:
			continue

		if status in CHARGED:
			group   = "Charged (Billable)"
			charged = "Yes"
			charged_total += count
		elif status in NOT_CHARGED:
			group   = "Not Charged"
			charged = "No"
			not_charged_total += count
		else:
			group   = "In Flight"
			charged = "-"

		data.append({
			"group":   group,
			"status":  status,
			"count":   count,
			"charged": charged,
		})

	total = charged_total + not_charged_total

	# ── Summary rows (blank group separator + totals) ─────────────────────────
	if data:
		data.append({"group": "", "status": "", "count": None, "charged": ""})
		data.append({
			"group":   "TOTAL",
			"status":  "Charged (Billable)",
			"count":   charged_total,
			"charged": "Yes",
		})
		data.append({
			"group":   "TOTAL",
			"status":  "Not Charged",
			"count":   not_charged_total,
			"charged": "No",
		})
		data.append({
			"group":   "TOTAL",
			"status":  "All Scans",
			"count":   total,
			"charged": "",
		})
		if scans_remaining is not None:
			label_suffix = " (Live)" if balance_source == "live" else " (Cached)"
			if balance_source == "live" and scans_allowed_live is not None:
				data.append({
					"group":   "QUOTA",
					"status":  "Total Allocated" + label_suffix,
					"count":   scans_allowed_live,
					"charged": "",
				})
				data.append({
					"group":   "QUOTA",
					"status":  "Scans Used" + label_suffix,
					"count":   scans_used_live,
					"charged": "",
				})
			data.append({
				"group":   "QUOTA",
				"status":  "Remaining Balance" + label_suffix,
				"count":   scans_remaining,
				"charged": "",
			})

	# ── Chart — donut by status (charged statuses vs not charged) ─────────────
	chart_labels  = []
	chart_values  = []
	chart_colors  = []

	for status in _STATUS_ORDER:
		count = counts.get(status, 0)
		if count:
			chart_labels.append(status)
			chart_values.append(count)
			chart_colors.append(_STATUS_COLOR.get(status, "#999"))

	chart = None
	if chart_labels:
		chart = {
			"type": "donut",
			"data": {
				"labels": chart_labels,
				"datasets": [{"values": chart_values}],
			},
			"colors": chart_colors,
			"height": 280,
		}

	return columns, data, None, chart
