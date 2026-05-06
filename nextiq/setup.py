import frappe

_CRM_CUSTOM_FIELD = "Card Scan Log-crm_lead"


def after_install():
	from nextiq.version_check import check_service_version
	check_service_version()
	_sync_crm_fields()


def after_migrate():
	from nextiq.version_check import check_service_version
	check_service_version()
	_sync_crm_fields()


def after_app_install(app_name):
	if app_name == "crm":
		_add_crm_fields()


def after_app_uninstall(app_name):
	if app_name == "crm":
		_remove_crm_fields()


def _sync_crm_fields():
	if "crm" in frappe.get_installed_apps():
		_add_crm_fields()
	else:
		_remove_crm_fields()


def _add_crm_fields():
	if frappe.db.exists("Custom Field", _CRM_CUSTOM_FIELD):
		return
	frappe.get_doc({
		"doctype": "Custom Field",
		"dt": "Card Scan Log",
		"fieldname": "crm_lead",
		"fieldtype": "Link",
		"options": "CRM Lead",
		"label": "CRM Lead",
		"read_only": 1,
		"insert_after": "lead",
	}).insert(ignore_permissions=True)
	frappe.db.commit()


def _remove_crm_fields():
	if not frappe.db.exists("Custom Field", _CRM_CUSTOM_FIELD):
		return
	frappe.delete_doc("Custom Field", _CRM_CUSTOM_FIELD, ignore_permissions=True)
	frappe.db.commit()
