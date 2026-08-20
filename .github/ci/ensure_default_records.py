# Run via: env/bin/python .github/ci/ensure_default_records.py test_site
# (from the bench root — see ci.yml)
#
# CI-only test-environment setup, not part of nextiq itself: Frappe's test
# runner auto-creates a test Company record for any app under test once
# erpnext is installed, which cascades into ERPNext code that expects a
# set of standard root/default records to already exist — "Warehouse
# Type: Transit", "Customer Group: All Customer Groups", "Territory: All
# Territories", "Item Group: All Item Groups", and others in the same
# family. Those are normally created by ERPNext's own Setup Wizard, which
# the test runner never runs — it inserts a bare test Company directly.
# On some version-15 point releases this same gap has also been reported
# as a real bug users hit through the Setup Wizard UI itself (e.g.
# frappe/erpnext#42309, #43261, #43262, #28928), so it isn't purely a
# test-runner quirk either way — none of it is a nextiq issue.
#
# Rather than recreate each individual missing record by hand as they
# turn up one at a time, call the actual function ERPNext itself uses to
# seed all of them: erpnext.setup.setup_wizard.operations.install_fixtures
# .install(). Every record it creates goes through insert(..., ignore_if_
# duplicate=True) wrapped in its own savepoint/rollback, so it's safe to
# call even when some of this data already exists (e.g. on version-16,
# where it's normally fine already).
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

from erpnext.setup.setup_wizard.operations.install_fixtures import install as install_erpnext_fixtures

# country isn't optional despite the default: get_preset_records() uses it
# unconditionally to build a home-country Territory and Address Template.
# The value itself doesn't matter for CI seed data — just needs to be real.
install_erpnext_fixtures(country="India")
# Standalone CI script, outside any request/transaction context.
frappe.db.commit()  # nosemgrep
frappe.destroy()
