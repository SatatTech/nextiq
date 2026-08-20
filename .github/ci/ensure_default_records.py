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
# Separately: Frappe's test runner reliably auto-creates dependencies for
# plain Link fields (e.g. Lead.territory -> Territory), but not reliably
# for Dynamic Link fields — e.g. Opportunity's test record references a
# test Lead ("_T-Lead-00001") through a Dynamic Link, and on version-15
# that Lead was never created first, so the reference fails to resolve.
# Pre-create Lead's own test records directly (which correctly cascades
# into Territory, a plain Link) so it already exists by the time anything
# needs it through a Dynamic Link instead.
#
# frappe.tests.utils.make_test_records only exists on version-16 (a
# package restructure) — frappe.test_runner.make_test_records is the
# version-portable path: the real implementation on version-15, a
# functional deprecated wrapper forwarding to the same place on
# version-16. Also set the test-mode flags the real test runner always
# sets before this point (frappe.local.flags.in_test and, on version-16,
# frappe.in_test) — without them, code paths that check "are we in a
# test?" behave as if this were production, e.g. User.validate() runs
# full password-strength enforcement instead of skipping it, which broke
# ERPNext's own test bootstrap (erpnext.tests.utils.BootStrapTestData,
# imported as a side effect of loading Lead's test module) trying to
# create its standard test user with a deliberately weak placeholder
# password.
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

from frappe.test_runner import make_test_records

make_test_records("Lead", commit=True)

# Standalone CI script, outside any request/transaction context.
frappe.db.commit()  # nosemgrep
frappe.destroy()
