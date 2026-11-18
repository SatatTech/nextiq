import frappe

_CRM_CUSTOM_FIELD = "Card Scan Log-crm_lead"


def after_install():
	from nextiq.version_check import check_service_version

	check_service_version()
	_sync_crm_fields()
	_sync_lead_field()
	_ensure_lead_destination()


def after_migrate():
	from nextiq.version_check import check_service_version

	check_service_version()
	_sync_crm_fields()
	_sync_lead_field()
	_ensure_lead_destination()


def after_app_install(app_name):
	if app_name == "crm":
		_add_crm_fields()
	if app_name in ("crm", "erpnext"):
		_sync_lead_field()
		_ensure_lead_destination()


def after_app_uninstall(app_name):
	if app_name == "crm":
		_remove_crm_fields()
	if app_name in ("crm", "erpnext"):
		_sync_lead_field()
		_ensure_lead_destination()


def _ensure_lead_destination():
	"""Pick a valid Create Lead In value for the apps installed on this site
	(ERPNext if present, else Frappe CRM). NextIQ Settings.validate() does the
	correction, so a plain save is enough."""
	try:
		settings = frappe.get_single("NextIQ Settings")
		before = settings.lead_destination
		settings.validate_lead_destination()
		if settings.lead_destination != before:
			frappe.db.set_single_value("NextIQ Settings", "lead_destination", settings.lead_destination)
			frappe.db.commit()
	except Exception:
		frappe.log_error("NextIQ: could not set default lead destination", frappe.get_traceback())


def _sync_lead_field():
	"""Card Scan Log.lead links to ERPNext's Lead doctype. Without ERPNext that
	field is meaningless, so hide it and show the CRM Lead field in its place."""
	from frappe.custom.doctype.property_setter.property_setter import make_property_setter

	has_erpnext = "erpnext" in frappe.get_installed_apps()
	if has_erpnext:
		frappe.db.delete(
			"Property Setter",
			{
				"doc_type": "Card Scan Log",
				"field_name": "lead",
				"property": "hidden",
			},
		)
	else:
		make_property_setter("Card Scan Log", "lead", "hidden", 1, "Check", validate_fields_for_doctype=False)
	frappe.clear_cache(doctype="Card Scan Log")
	frappe.db.commit()


def _sync_crm_fields():
	if "crm" in frappe.get_installed_apps():
		_add_crm_fields()
	else:
		_remove_crm_fields()


def _add_crm_fields():
	if frappe.db.exists("Custom Field", _CRM_CUSTOM_FIELD):
		return
	frappe.get_doc(
		{
			"doctype": "Custom Field",
			"dt": "Card Scan Log",
			"fieldname": "crm_lead",
			"fieldtype": "Link",
			"options": "CRM Lead",
			"label": "CRM Lead",
			"read_only": 1,
			"in_list_view": 1,
			"insert_after": "lead",
		}
	).insert(ignore_permissions=True)
	frappe.db.commit()


def _remove_crm_fields():
	if not frappe.db.exists("Custom Field", _CRM_CUSTOM_FIELD):
		return
	frappe.delete_doc("Custom Field", _CRM_CUSTOM_FIELD, ignore_permissions=True)
	# Runs from setup/uninstall hooks outside a request, so nothing else commits this.
	frappe.db.commit()  # nosemgrep
