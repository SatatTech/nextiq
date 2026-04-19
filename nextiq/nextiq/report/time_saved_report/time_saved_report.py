import frappe
from frappe.utils import add_months, add_days, today


# Daily/Weekly → line (many points, trend matters)
# Monthly/Quarterly/Yearly → bar (few discrete periods, magnitude matters)
_CHART_TYPE = {
	"Daily": "line", "Weekly": "line",
	"Monthly": "bar", "Quarterly": "bar", "Yearly": "bar",
}

_COL_LABEL = {
	"Daily": "Date", "Weekly": "Week", "Monthly": "Month",
	"Quarterly": "Quarter", "Yearly": "Year",
}


def execute(filters=None):
	filters   = frappe._dict(filters or {})
	period  = filters.get("period") or "Monthly"
	to_date = filters.get("to_date") or today()
	# Daily defaults to last 14 days → 15 points (day -14 … today)
	# All other periods default to last 12 months
	if not filters.get("from_date"):
		from_date = add_days(to_date, -14) if period == "Daily" else add_months(to_date, -12)
	else:
		from_date = filters.get("from_date")

	columns = [
		{"fieldname": "period_label", "label": _COL_LABEL.get(period, "Period"), "fieldtype": "Data", "width": 140},
		{"fieldname": "leads_created", "label": "Leads Created",     "fieldtype": "Int", "width": 140},
		{"fieldname": "minutes_saved", "label": "Time Saved (mins)", "fieldtype": "Int", "width": 160},
	]

	rows = _fetch_rows(period, from_date, to_date)

	data = [
		{"period_label": r.period_label, "leads_created": r.leads_created, "minutes_saved": r.minutes_saved}
		for r in rows
	]

	chart = {
		"type": _CHART_TYPE.get(period, "bar"),
		"data": {
			"labels":   [r.period_label for r in rows],
			"datasets": [{"name": "Time Saved (mins)", "values": [r.minutes_saved for r in rows]}],
		},
		"colors": ["#2ecc71"],
		"axisOptions": {"xIsSeries": 1},
	}

	return columns, data, None, chart


def _fetch_rows(period, from_date, to_date):
	params = {"from_date": from_date, "to_date": to_date}

	if period == "Daily":
		return frappe.db.sql("""
			SELECT
				DATE_FORMAT(submitted_at, '%%d %%b %%Y') AS period_label,
				DATE(submitted_at)                        AS sort_key,
				COUNT(*)     AS leads_created,
				COUNT(*) * 2 AS minutes_saved
			FROM `tabCard Scan Log`
			WHERE status = 'Success'
			  AND DATE(submitted_at) BETWEEN %(from_date)s AND %(to_date)s
			GROUP BY sort_key, period_label
			ORDER BY sort_key
		""", params, as_dict=True)

	if period == "Weekly":
		return frappe.db.sql("""
			SELECT
				CONCAT('W', WEEK(submitted_at, 3), ' ', YEAR(submitted_at)) AS period_label,
				YEARWEEK(submitted_at, 3) AS sort_key,
				COUNT(*)     AS leads_created,
				COUNT(*) * 2 AS minutes_saved
			FROM `tabCard Scan Log`
			WHERE status = 'Success'
			  AND DATE(submitted_at) BETWEEN %(from_date)s AND %(to_date)s
			GROUP BY sort_key, period_label
			ORDER BY sort_key
		""", params, as_dict=True)

	if period == "Quarterly":
		return frappe.db.sql("""
			SELECT
				CONCAT('Q', QUARTER(submitted_at), ' ', YEAR(submitted_at)) AS period_label,
				CONCAT(YEAR(submitted_at), '-', LPAD(QUARTER(submitted_at), 2, '0')) AS sort_key,
				COUNT(*)     AS leads_created,
				COUNT(*) * 2 AS minutes_saved
			FROM `tabCard Scan Log`
			WHERE status = 'Success'
			  AND DATE(submitted_at) BETWEEN %(from_date)s AND %(to_date)s
			GROUP BY sort_key, period_label
			ORDER BY sort_key
		""", params, as_dict=True)

	if period == "Yearly":
		return frappe.db.sql("""
			SELECT
				DATE_FORMAT(submitted_at, '%%Y') AS period_label,
				DATE_FORMAT(submitted_at, '%%Y') AS sort_key,
				COUNT(*)     AS leads_created,
				COUNT(*) * 2 AS minutes_saved
			FROM `tabCard Scan Log`
			WHERE status = 'Success'
			  AND DATE(submitted_at) BETWEEN %(from_date)s AND %(to_date)s
			GROUP BY sort_key, period_label
			ORDER BY sort_key
		""", params, as_dict=True)

	# Monthly (default)
	return frappe.db.sql("""
		SELECT
			DATE_FORMAT(submitted_at, '%%b %%Y') AS period_label,
			DATE_FORMAT(submitted_at, '%%Y-%%m') AS sort_key,
			COUNT(*)     AS leads_created,
			COUNT(*) * 2 AS minutes_saved
		FROM `tabCard Scan Log`
		WHERE status = 'Success'
		  AND DATE(submitted_at) BETWEEN %(from_date)s AND %(to_date)s
		GROUP BY sort_key, period_label
		ORDER BY sort_key
	""", params, as_dict=True)
