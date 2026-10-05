# Run via: env/bin/python .github/ci/ensure_default_records.py test_site
# (from the bench root — see ci.yml)
#
# CI-only test-environment setup, not part of nextiq itself: Frappe's test
# runner auto-creates test records (Company, Contact, ...) for any app
# under test once erpnext is installed, which cascades into code that
# expects a whole set of standard default records to already exist —
# "Warehouse Type: Transit", "Customer Group: All Customer Groups",
# "Gender: Female", and others in the same family, from both Frappe core
# and ERPNext. All of these are normally created together when a real
# user completes the Setup Wizard, which the test runner never runs — it
# inserts bare test records directly. On some version-15 point releases
# this same gap has also been reported as a real bug users hit through
# the Setup Wizard UI itself (e.g. frappe/erpnext#42309, #43261, #43262,
# #28928), so it isn't purely a test-runner quirk either way — none of it
# is a nextiq issue.
#
# Rather than recreate each individual missing record by hand as they
# turn up one at a time, call the same two functions the real Setup
# Wizard calls, in the same order (frappe.desk.page.setup_wizard.
# setup_wizard.run_post_setup_complete): Frappe core's own fixtures
# first, then ERPNext's. Every record either one creates goes through
# insert(..., ignore_if_duplicate=True), most wrapped in their own
# savepoint/rollback, so both are safe to call even when some of this
# data already exists (e.g. on version-16, where it's normally fine
# already).
#
# frappe.local.flags.in_test (and, on version-16, frappe.in_test) are set
# below because the real bench run-tests always sets them before this
# point is reached, and some validations key off them directly (e.g.
# User.validate() only skips password-strength enforcement when
# frappe.in_test is set) — without it, this script behaves as if it were
# production, not test setup.
#
# version-15 only: erpnext/crm/doctype/opportunity/test_records.json
# references a Lead by hardcoded name ("_T-Lead-00001") through a Dynamic
# Link field ("Party") — Dynamic Links aren't reliably auto-walked as
# dependencies the way plain Link fields are, so that Lead is never
# created before something needs it. An earlier attempt used
# frappe.test_runner.make_test_records("Lead", commit=True) to pre-create
# it, but that recursively walks Frappe's *entire* test dependency graph
# from the given doctype (confirmed via a 22+-level-deep traceback), and
# on this codebase's actual graph that walk hit both a missing mandatory
# field on an auto-generated Opportunity test record and a doctype
# ("Payment Gateway") belonging to an app that isn't even installed here
# ("payments") — worse than the original problem.
#
# So instead: create exactly the two records needed, directly, matching
# the real field values from Territory's and Lead's own test_records.json
# (confirmed against frappe/erpnext's actual version-15 branch source) —
# no graph-walking at all. Confirmed version-16 has no equivalent
# Opportunity/Territory test fixtures referencing a Lead this way, so
# these two extra records are a genuine no-op there, not a
# version-conditional hack.
#
# Plain script rather than `bench execute`: that command resolves dotted
# paths through frappe.get_attr(), which requires the first segment to be
# a real *installed app name*, not just an importable module on
# PYTHONPATH — it isn't a generic Python import, so a standalone CI script
# can never be reached that way regardless of PYTHONPATH.
import os
import sys

import frappe

site = sys.argv[1]
# bench's own CLI always chdir()s into <bench_root>/sites before running any
# command — Frappe internals rely on that (e.g. the logger builds its log
# path as "../logs", relative to CWD). Replicate that here so frappe.init()
# and everything downstream of it behaves exactly like a real bench command.
os.chdir("sites")
frappe.init(site=site)
frappe.connect()
frappe.local.flags.in_test = True
frappe.in_test = True  # version-16 only; harmless to set unconditionally on version-15

from erpnext.setup.setup_wizard.operations.install_fixtures import install as install_erpnext_fixtures
from frappe.desk.page.setup_wizard.install_fixtures import install as install_frappe_fixtures

install_frappe_fixtures()

# country isn't optional despite the default: get_preset_records() uses it
# unconditionally to build a home-country Territory and Address Template.
# The value itself doesn't matter for CI seed data — just needs to be real.
install_erpnext_fixtures(country="India")


def create_opportunity_test_dependencies():
	territory = frappe.get_doc(
		{
			"doctype": "Territory",
			"territory_name": "_Test Territory",
			"parent_territory": "All Territories",
			"is_group": 0,
		}
	)
	territory.insert(ignore_permissions=True, ignore_if_duplicate=True)

	# naming_series mirrors exactly what Frappe's own test-record machinery
	# does for a doctype named via naming_series (frappe/tests/utils/
	# generators.py's _try_create): the counter then assigns "_T-Lead-00001"
	# on a fresh site, matching what Opportunity's fixture hardcodes.
	lead = frappe.get_doc(
		{
			"doctype": "Lead",
			"email_id": "test_lead@example.com",
			"lead_name": "_Test Lead",
			"status": "Open",
			"territory": "_Test Territory",
		}
	)
	lead.naming_series = "_T-Lead-"
	lead.insert(ignore_permissions=True, ignore_if_duplicate=True)


create_opportunity_test_dependencies()

# Standalone CI script, outside any request/transaction context.
frappe.db.commit()  # nosemgrep
frappe.destroy()
