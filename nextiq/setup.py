import frappe

_CRM_CUSTOM_FIELD = "Card Scan Log-crm_lead"


NO_LEAD_APP_MSG = (
	"NextIQ needs Frappe CRM or ERPNext to create leads. "
	"Please install at least one of them on this site, then install NextIQ."
)


LEAD_APPS = ("erpnext", "crm")


def before_install():
	"""NextIQ needs ERPNext or Frappe CRM (either one is enough).

	- Neither on the site and neither in the bench: stop with a short message.
	- On the bench but not yet on the site: install them first (one or both).
	"""
	installed = frappe.get_installed_apps()
	if any(app in installed for app in LEAD_APPS):
		return

	in_bench = [app for app in LEAD_APPS if app in frappe.get_all_apps()]
	if not in_bench:
		# IncompatibleApp is printed by `bench install-app` as a short message
		# (no traceback) and aborts the install before anything is created.
		raise frappe.IncompatibleApp(NO_LEAD_APP_MSG)

	from frappe.installer import install_app

	in_install = frappe.flags.in_install
	for app in in_bench:
		install_app(app)
	# the nested install resets this flag; NextIQ's own install is still running
	frappe.flags.in_install = in_install


def after_install():
	from nextiq.version_check import check_service_version
	check_service_version()
	_sync_lead_field()
	_sync_crm_fields()
	_ensure_lead_destination()


def after_migrate():
	from nextiq.version_check import check_service_version
	check_service_version()
	_sync_lead_field()
	_sync_crm_fields()
	_ensure_lead_destination()


def after_app_install(app_name):
	if app_name in ("crm", "erpnext"):
		_sync_lead_field()
	if app_name == "crm":
		_add_crm_fields()
	if app_name in ("crm", "erpnext"):
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
	from nextiq.nextiq.doctype.nextiq_settings.nextiq_settings import get_default_lead_destination

	if not get_default_lead_destination():
		return  # neither app installed; the Settings form shows a message instead
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
	doctype does not exist and Frappe refuses to validate Card Scan Log (which
	breaks adding the CRM Lead field), so turn it into a hidden plain field."""
	from frappe.custom.doctype.property_setter.property_setter import make_property_setter

	has_erpnext = "erpnext" in frappe.get_installed_apps()
	if has_erpnext:
		frappe.db.delete(
			"Property Setter",
			{
				"doc_type": "Card Scan Log",
				"field_name": "lead",
				"property": ("in", ("hidden", "fieldtype", "options")),
			},
		)
	else:
		for prop, value, ptype in (
			("fieldtype", "Data", "Select"),
			("options", "", "Text"),
			("hidden", 1, "Check"),
		):
			make_property_setter(
				"Card Scan Log", "lead", prop, value, ptype, validate_fields_for_doctype=False
			)
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
