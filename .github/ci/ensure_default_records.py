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
# NOTE: an earlier version of this script also called
# frappe.test_runner.make_test_records("Lead", commit=True) here, to
# pre-create a Lead that erpnext/crm/doctype/opportunity/test_records.json
# references by hardcoded name through a Dynamic Link field ("Party") —
# Dynamic Links aren't reliably auto-walked as dependencies the way plain
# Link fields are, so that Lead was never created before something needed
# it. That fix was reverted: make_test_records() recursively walks
# Frappe's *entire* test dependency graph from the given doctype, not just
# its immediate needs — confirmed via traceback showing 22+ levels of
# recursion — and on this codebase's actual dependency graph that walk
# hits both a missing mandatory field on an auto-generated Opportunity
# test record and, worse, a doctype ("Payment Gateway") belonging to an
# app that isn't even installed here ("payments"). Each attempt to work
# around that made things worse, not better, so the Dynamic Link gap is
# left as a known, accepted limitation on version-15 rather than chased
# further.
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

# Standalone CI script, outside any request/transaction context.
frappe.db.commit()  # nosemgrep
frappe.destroy()
