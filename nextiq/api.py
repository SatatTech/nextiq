# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import base64
import hashlib
import hmac
import ipaddress
import secrets
import traceback

import frappe
import requests

import nextiq
from nextiq.constants import SERVICE_URL
from nextiq.version_check import _version_lt

# Fields allowed when creating a Lead from scan data — mirrors the service-side list
_ALLOWED_LEAD_FIELDS = frozenset({
	"salutation", "first_name", "middle_name", "last_name",
	"gender", "job_title", "email_id", "mobile_no", "whatsapp_no",
	"phone", "phone_ext", "company_name", "website",
	"fax", "city", "state", "country",
})
_MAX_FIELD_LEN = 500   # max characters per Lead field value

# Map Frappe DocType names (as they appear in "Could not find X: Y" errors) to
# the Lead field name, so _find_bad_field can strip the offending field.
_LINK_DOCTYPE_TO_FIELD = {
	"country":    "country",
	"salutation": "salutation",
	"Country":    "country",
	"Salutation": "salutation",
}

# Maps lowercase field labels (as Frappe uses them in error messages) to Lead field names.
# Lets _find_bad_field identify any field from a ValidationError, not just link fields.
_FIELD_LABEL_TO_NAME = {
	"salutation":   "salutation",
	"first name":   "first_name",
	"middle name":  "middle_name",
	"last name":    "last_name",
	"gender":       "gender",
	"job title":    "job_title",
	"email id":     "email_id",
	"email":        "email_id",
	"mobile no":    "mobile_no",
	"mobile":       "mobile_no",
	"whatsapp no":  "whatsapp_no",
	"whatsapp":     "whatsapp_no",
	"phone":        "phone",
	"phone ext":    "phone_ext",
	"company name": "company_name",
	"company":      "company_name",
	"website":      "website",
	"fax":          "fax",
	"city":         "city",
	"state":        "state",
	"country":      "country",
}


def _find_bad_field(error_msg, data):
	"""
	Parse a Frappe ValidationError message and return the Lead field name
	that caused it, or None if it cannot be determined.
	"""
	import re
	# "Could not find {DocType}: {value}" — Link field resolution failure
	m = re.search(r"Could not find ([\w ]+):", error_msg)
	if m:
		doctype = m.group(1).strip()
		field = _LINK_DOCTYPE_TO_FIELD.get(doctype) or _LINK_DOCTYPE_TO_FIELD.get(doctype.lower())
		if field and field in data:
			return field
	# Check if any field's current value appears verbatim in the error message
	for field, value in data.items():
		if value and str(value) in error_msg:
			return field
	# Check if any field label appears in the error message
	# (e.g. "Value for Gender must be one of …", "Invalid Email Id")
	err_lower = error_msg.lower()
	for label, field in _FIELD_LABEL_TO_NAME.items():
		if label in err_lower and field in data:
			return field
	return None


class _QuotaExceededError(Exception):
    pass


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_client_ip():
	"""
	Return the best-available client IP.

	Priority:
	  1. X-Real-IP   — set by nginx/trusted proxy; client cannot forge it.
	  2. X-Forwarded-For (rightmost valid entry) — added by the nearest trusted
	     proxy, not the client. The leftmost entry is client-controlled and forgeable.
	  3. remote_addr — correct when Frappe is directly exposed (no proxy).
	"""
	req = frappe.request
	real_ip = (req.headers.get("X-Real-IP") or "").strip()
	if real_ip:
		try:
			ipaddress.ip_address(real_ip)
			return real_ip
		except ValueError:
			pass
	forwarded = req.headers.get("X-Forwarded-For") or ""
	for candidate in reversed([x.strip() for x in forwarded.split(",") if x.strip()]):
		try:
			ipaddress.ip_address(candidate)
			return candidate
		except ValueError:
			continue
	return req.remote_addr or "unknown"


def _rate_limit(key, max_per_minute):
	"""
	Sliding-window rate limit via Redis INCR + EXPIRE.
	Returns True (allow) or False (block).
	Fails open if Redis is unavailable.
	"""
	try:
		pipe = frappe.cache().redis_client.pipeline()
		pipe.incr(key)
		pipe.expire(key, 60)
		count = pipe.execute()[0]
		return count <= max_per_minute
	except Exception:
		frappe.logger("nextiq").warning(
			f"Rate limit Redis check failed for key '{key}' — allowing (fail-open)"
		)
		return True


# ── Public endpoints (called from card-scan portal JS) ───────────────────────

@frappe.whitelist()
def submit_card_scan(merged_image_base64, filename="business_card.jpg"):
	"""
	Receive merged business card image from the portal.
	Generates job_id + cb_secret, saves image, enqueues _fire_scan_to_service.

	Returns immediately: {"log_name": str}
	The browser can close after this — Lead is created via background + callback.
	"""
	# Block if the installed app is below the service-required minimum version
	_service_min = frappe.db.get_value(
		"NextIQ Settings", "NextIQ Settings", "service_min_version"
	) or ""
	if _service_min and _version_lt(nextiq.__version__, _service_min):
		frappe.throw(
			"The NextIQ app on this site requires an update before scanning can continue. "
			"Please ask your administrator to update the app.",
			title="App Update Required",
		)

	# Rate limit: 10 scans per minute per user (hash user to keep plaintext out of Redis)
	_user_hash = hashlib.sha256(frappe.session.user.encode()).hexdigest()
	if not _rate_limit(f"nextiq_scan:{_user_hash}", max_per_minute=10):
		frappe.throw(
			"Too many scan requests. Please wait a moment and try again.",
			title="Rate Limited",
		)

	if "," in merged_image_base64:
		merged_image_base64 = merged_image_base64.split(",")[1]

	# Guard against oversized payloads — business cards don't need more than ~7.5 MB
	MAX_B64 = 10 * 1024 * 1024  # 10 MB base64 ≈ 7.5 MB raw
	if len(merged_image_base64) > MAX_B64:
		frappe.throw("Image is too large (max 7.5 MB). Please use a smaller image.", title="Image Too Large")

	# Generate credentials for this scan job
	job_id    = secrets.token_urlsafe(32)
	cb_secret = secrets.token_urlsafe(32)

	log = frappe.get_doc({
		"doctype": "Card Scan Log",
		"status": "Pending",
		"submitted_at": frappe.utils.now(),
		"job_id": job_id,
		"cb_secret": cb_secret,
		"scanned_by": frappe.session.user,
	})
	log.insert(ignore_permissions=True)
	frappe.db.commit()

	# Save the merged image as a private Frappe file
	try:
		file_content = base64.b64decode(merged_image_base64)
		file_doc = frappe.get_doc({
			"doctype": "File",
			"file_name": f"card_scan_{log.name}.jpg",
			"content": file_content,
			"is_private": 1,
			"attached_to_doctype": "Card Scan Log",
			"attached_to_name": log.name,
		})
		file_doc.save(ignore_permissions=True)
		frappe.db.set_value("Card Scan Log", log.name, "merged_image", file_doc.file_url)
		frappe.db.commit()
	except Exception as e:
		frappe.db.set_value("Card Scan Log", log.name, {
			"status": "Failed",
			"error_message": f"Image save failed: {str(e)[:400]}",
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
		return {"log_name": log.name}

	# Enqueue lightweight job — it fires the request and returns in <1s
	frappe.enqueue(
		"nextiq.api._fire_scan_to_service",
		log_name=log.name,
		queue="long",
		timeout=60,
		now=False,
	)

	return {"log_name": log.name}


@frappe.whitelist(allow_guest=True)
def scan_callback(job_id, cb_secret, success, data=None, error=None,
                  message=None, scans_used=None, scans_allowed=None, scans_remaining=None):
	"""
	Called by nextiq_service when scan processing is complete.

	Security:
	  - allow_guest=True is intentional — this is server-to-server, no session exists.
	  - cb_secret is a single-use token generated by nextiq.test at submit time.
	  - Comparison uses hmac.compare_digest to prevent timing attacks.
	  - cb_secret is cleared from DB after first successful callback (prevents replay).
	"""
	# Rate limit: 60 callbacks per minute per IP — real service sends 1 per scan
	remote_ip = _get_client_ip()
	if not _rate_limit(f"nextiq_cb:{remote_ip}", max_per_minute=60):
		return {"success": False, "error": "rate_limited"}

	if not job_id or not cb_secret:
		return {"success": False, "error": "missing_params"}

	log_data = frappe.db.get_value(
		"Card Scan Log", {"job_id": job_id}, ["name", "scanned_by"], as_dict=True
	)
	if not log_data:
		return {"success": False, "error": "invalid_job_id"}
	log_name = log_data.name
	scanned_by = log_data.scanned_by

	# Constant-time secret comparison — prevents timing-based enumeration
	stored_secret = frappe.db.get_value("Card Scan Log", log_name, "cb_secret") or ""
	if not stored_secret or not hmac.compare_digest(stored_secret, str(cb_secret)):
		frappe.log_error(
			f"Invalid cb_secret received for job_id={job_id}",
			"NextIQ: Callback Auth Failed",
		)
		return {"success": False, "error": "invalid_secret"}

	# Idempotency guard — if already terminal, accept silently (handles callback retries)
	current_status = frappe.db.get_value("Card Scan Log", log_name, "status")
	if current_status not in ("Pending", "Processing"):
		return {"success": True, "note": "already_processed"}

	# Explicit cast — prevents "false" string being truthy when sent form-encoded
	success = success if isinstance(success, bool) else str(success).lower() == "true"

	if success:
		lead_name = None
		if data and isinstance(data, dict):
			# Re-validate on this side: only known Lead fields, values truncated to 500 chars.
			# Defense-in-depth even though the service already filters by ALLOWED_LEAD_FIELDS.
			data = {
				k: str(v)[:_MAX_FIELD_LEN]
				for k, v in data.items()
				if k in _ALLOWED_LEAD_FIELDS and v not in (None, "")
			}
		if data:
			skipped_fields = {}
			try:
				# Retry loop: on ValidationError, strip the offending field and try again.
				# This handles AI values that don't match ERPNext options (e.g. country="BHARAT").
				for _attempt in range(len(data) + 1):
					try:
						lead_doc_data = {"doctype": "Lead", **data}
						if scanned_by and scanned_by != "Guest":
							lead_doc_data["lead_owner"] = scanned_by
						lead = frappe.get_doc(lead_doc_data)
						lead.insert(ignore_permissions=True)
						frappe.db.commit()
						lead_name = lead.name
						break
					except frappe.exceptions.DuplicateEntryError:
						raise
					except frappe.ValidationError as e:
						frappe.db.rollback()
						bad_field = _find_bad_field(str(e), data)
						if bad_field:
							skipped_fields[bad_field] = data.pop(bad_field)
						else:
							raise  # can't identify which field — propagate
				else:
					raise frappe.ValidationError("All fields were invalid; no lead could be created.")

				# Add a comment listing any skipped fields so the sales rep knows what was dropped
				if skipped_fields:
					# Null out the skipped fields — without this, Frappe applies doctype
					# defaults (e.g. country defaults to "India") when the field is absent.
					frappe.db.set_value("Lead", lead_name,
						{f: None for f in skipped_fields})
					lines = ["<b>NextIQ: the following fields were skipped (invalid values):</b><ul>"]
					for f, v in skipped_fields.items():
						lines.append(f"<li><b>{f}</b>: {v}</li>")
					lines.append("</ul>")
					frappe.get_doc({
						"doctype": "Comment",
						"comment_type": "Info",
						"reference_doctype": "Lead",
						"reference_name": lead_name,
						"content": "".join(lines),
					}).insert(ignore_permissions=True)
					frappe.db.commit()

			except frappe.exceptions.DuplicateEntryError as e:
				err_msg = str(e)[:500] or "A lead with this email address already exists."
				frappe.db.rollback()
				frappe.db.set_value("Card Scan Log", log_name, {
					"status": "Duplicate Lead",
					"error_message": err_msg,
					"processed_at": frappe.utils.now(),
					"cb_secret": "",
				})
				frappe.db.commit()
				_send_scan_notification(log_name, "duplicate_lead", message=err_msg)
				return {"success": False, "error": "duplicate_lead"}
			except frappe.ValidationError as e:
				err_msg = str(e)[:500] or "AI data could not be saved as a Lead — all field values were invalid."
				frappe.db.rollback()
				frappe.db.set_value("Card Scan Log", log_name, {
					"status": "Invalid Data",
					"error_message": err_msg,
					"ai_response": frappe.as_json(data or {}),
					"processed_at": frappe.utils.now(),
					"cb_secret": "",
				})
				frappe.db.commit()
				_send_scan_notification(log_name, "invalid_data", message=err_msg)
				frappe.enqueue(
					"nextiq.api._send_feedback_to_service",
					log_name=log_name,
					feedback_type="Invalid Data",
					queue="short",
					timeout=30,
					now=False,
				)
				return {"success": False, "error": "invalid_lead_data"}
			except Exception as e:
				frappe.log_error(traceback.format_exc(), f"NextIQ: Lead creation failed for {log_name}")
				err_msg = str(e)[:500] or "Lead could not be created from scan data."
				frappe.db.rollback()
				frappe.db.set_value("Card Scan Log", log_name, {
					"status": "Failed",
					"error_message": err_msg,
					"processed_at": frappe.utils.now(),
					"cb_secret": "",
				})
				frappe.db.commit()
				_send_scan_notification(log_name, "failed", message=err_msg)
				frappe.enqueue(
					"nextiq.api._send_feedback_to_service",
					log_name=log_name,
					feedback_type="Failed",
					queue="short",
					timeout=30,
					now=False,
				)
				return {"success": False, "error": "lead_creation_failed"}

		success_fields = {
			"status": "Success",
			"lead": lead_name,
			"processed_at": frappe.utils.now(),
			"ai_response": frappe.as_json(data or {}),
			"cb_secret": "",   # single-use — clear after successful callback
		}
		if scans_remaining is not None:
			success_fields["scans_remaining"] = scans_remaining
		frappe.db.set_value("Card Scan Log", log_name, success_fields)
		frappe.db.commit()
		_send_scan_notification(log_name, "success",
			lead_name=lead_name, scans_remaining=scans_remaining)

	else:
		status_map = {
			"quota_exceeded":     "Quota Exceeded",
			"not_a_business_card": "Invalid Image",
			"processing_failed":  "Failed",
			"suspended":          "Failed",
		}
		status = status_map.get(error or "", "Failed")

		update_fields = {
			"status": status,
			"error_message": message or "Scan failed.",
			"processed_at": frappe.utils.now(),
			"cb_secret": "",   # clear regardless of outcome
		}
		if scans_remaining is not None:
			update_fields["scans_remaining"] = scans_remaining
		frappe.db.set_value("Card Scan Log", log_name, update_fields)
		frappe.db.commit()
		_send_scan_notification(log_name, error or "failed",
			message=message, scans_remaining=scans_remaining)

	return {"success": True}


# ── Background job ────────────────────────────────────────────────────────────

def _fire_scan_to_service(log_name):
	"""
	Lightweight RQ job: load image, fire request to nextiq_service, return in <1s.

	nextiq_service enqueues its own background job, returns immediately with
	{"queued": true, "job_id": "..."}.

	The actual result arrives later via the scan_callback endpoint.
	"""
	logger = frappe.logger("nextiq")
	logger.info(f"[NextIQ] Firing scan to service: {log_name}")

	try:
		frappe.db.set_value("Card Scan Log", log_name, "status", "Processing")
		frappe.db.commit()

		settings = frappe.get_single("NextIQ Settings")
		if not settings.api_key:
			raise Exception("NextIQ Settings not configured. Please set the API Key.")

		api_key = settings.get_password("api_key")

		log = frappe.get_doc("Card Scan Log", log_name)
		if not log.merged_image:
			raise Exception("No image attached to this log.")
		if not log.job_id or not log.cb_secret:
			raise Exception("Scan log is missing job credentials. Please re-submit.")

		# Load image
		file_doc     = frappe.get_doc("File", {"file_url": log.merged_image})
		image_base64 = base64.b64encode(file_doc.get_content()).decode()

		# Build callback URL pointing back to this site
		callback_url = (
			frappe.utils.get_url()
			+ "/api/method/nextiq.api.scan_callback"
		)

		logger.info(f"[NextIQ] Calling service at {SERVICE_URL}, job_id={log.job_id}")

		try:
			response = requests.post(
				f"{SERVICE_URL}/api/method/nextiq_service.api.process_scan",
				json={
					# api_key is sent in the Authorization header, not the body,
					# so it never appears in Frappe's form_dict or debug logs.
					"image_base64":    image_base64,
					"filename":        log.merged_image.split("/")[-1] if log.merged_image else "business_card.jpg",
					"job_id":          log.job_id,
					"callback_url":    callback_url,
					"cb_secret":       log.cb_secret,
					"customer_log_id": log.name,
				},
				headers={
					"Content-Type": "application/json",
					"X-NextIQ-API-Key": api_key,
					"X-NextIQ-Client-Version": nextiq.__version__,
				},
				timeout=15,  # service should accept in <1s — short timeout
			)
		except requests.exceptions.ConnectionError:
			raise Exception(
				f"Cannot reach NextIQ Service at {SERVICE_URL}. "
				"Please contact support."
			)
		except requests.exceptions.Timeout:
			raise Exception(
				"NextIQ Service did not accept the job in time. "
				"The service may be down. Please try again."
			)

		if response.status_code == 503:
			raise Exception("NextIQ Service is temporarily unavailable (503). Please try again.")
		elif response.status_code == 502:
			raise Exception("NextIQ Service returned a bad gateway error (502). Please try again.")
		elif response.status_code >= 500:
			raise Exception(f"NextIQ Service returned a server error ({response.status_code}).")
		elif response.status_code == 402:
			raise _QuotaExceededError("Scan quota exhausted. Please contact the NextIQ team to top up.")
		elif response.status_code in (401, 403):
			raise Exception(
				f"NextIQ Service rejected the request ({response.status_code}). "
				"Please verify your API Key in NextIQ Settings."
			)
		elif response.status_code >= 400:
			raise Exception(f"NextIQ Service returned error {response.status_code}.")

		result = response.json().get("message", {})

		if result.get("error"):
			# Synchronous rejection (e.g. missing params, invalid key)
			raise Exception(result.get("message", "Service rejected the request."))

		if not result.get("queued"):
			raise Exception("Service did not confirm job was queued.")

		logger.info(
			f"[NextIQ] Job accepted. job_id={log.job_id}. "
			"RQ worker done — result will arrive via scan_callback."
		)
		# RQ job ends here in <1s. Lead creation happens in scan_callback.

	except _QuotaExceededError as e:
		logger.warning(f"[NextIQ] Quota exceeded for scan {log_name}: {e}")
		frappe.db.set_value("Card Scan Log", log_name, {
			"status": "Quota Exceeded",
			"error_message": str(e)[:1000],
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
		_send_scan_notification(log_name, "quota_exceeded", message=str(e))
	except Exception as e:
		logger.error(f"[NextIQ] Failed to fire scan {log_name}: {e}\n{traceback.format_exc()}")
		frappe.log_error(traceback.format_exc(), f"NextIQ: Fire Scan Failed: {log_name}")
		frappe.db.set_value("Card Scan Log", log_name, {
			"status": "Failed",
			"error_message": str(e)[:1000],
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
		_send_scan_notification(log_name, "failed", message=str(e))


# ── Feedback to service ───────────────────────────────────────────────────────

def _send_feedback_to_service(log_name, feedback_type):
	"""
	Fire scan feedback to nextiq_service for model training.

	Runs as an enqueued background job — errors are logged, never raised,
	so they never affect the customer-facing scan flow.
	"""
	try:
		log = frappe.get_doc("Card Scan Log", log_name)
		settings = frappe.get_single("NextIQ Settings")
		if not settings.api_key:
			return

		api_key = settings.get_password("api_key")

		requests.post(
			f"{SERVICE_URL}/api/method/nextiq_service.api.receive_scan_feedback",
			json={
				"job_id":          log.job_id,
				"feedback_type":   feedback_type,
				"error_message":   log.error_message or "",
				"ai_response":     log.ai_response or "",
				"customer_log_id": log.name,
			},
			headers={
				"Content-Type":    "application/json",
				"X-NextIQ-API-Key": api_key,
			},
			timeout=15,
		)
	except Exception:
		frappe.log_error(
			frappe.get_traceback(),
			f"NextIQ: Feedback Send Failed: {log_name}",
		)


# ── Email notification ────────────────────────────────────────────────────────

def _send_scan_notification(log_name, outcome, lead_name=None, message=None, scans_remaining=None):
	"""Send email to the ERPNext user who submitted the scan."""
	try:
		owner = frappe.db.get_value("Card Scan Log", log_name, "owner")
		user_email = frappe.db.get_value("User", owner, "email")
		if not user_email:
			return

		if outcome == "quota_exceeded":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Scan quota exhausted",
				message=(
					"<p>Your scan quota is exhausted. No more scans can be processed.</p>"
					"<p>Please contact the NextIQ team to increase your quota.</p>"
				),
				delayed=False,
			)

		elif outcome == "failed":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Card scan failed",
				message=(
					"<p>Your card scan could not be completed.</p>"
					+ (f"<p><strong>Reason:</strong> {message}</p>" if message else "")
					+ "<p>Please try scanning again.</p>"
				),
				delayed=False,
			)

	except Exception:
		frappe.log_error(
			frappe.get_traceback(),
			f"NextIQ: Email notification failed for {log_name}",
		)


# ── Time saved metric ────────────────────────────────────────────────────────

@frappe.whitelist()
def get_time_saved_minutes():
	"""Number Card data source: successful leads × 2 minutes per lead."""
	count = frappe.db.count("Card Scan Log", {"status": "Success"})
	return (count or 0) * 2


# ── Live balance proxy ────────────────────────────────────────────────────────

@frappe.whitelist()
def get_live_balance():
	"""
	Fetch live scan balance from nextiq_service.

	Requires a valid Frappe login session — API key is read server-side from
	NextIQ Settings and never exposed to the browser.

	Returns the service response dict, or {"success": False, ...} on error.
	"""
	settings = frappe.get_single("NextIQ Settings")
	if not settings.api_key:
		frappe.throw("NextIQ Settings not configured (API Key missing).",
					 title="Not Configured")

	api_key = settings.get_password("api_key")

	try:
		resp = requests.get(
			f"{SERVICE_URL}/api/method/nextiq_service.api.check_quota",
			headers={
				"X-NextIQ-API-Key": api_key,
				"Content-Type":     "application/json",
			},
			timeout=10,
		)
	except requests.exceptions.ConnectionError:
		frappe.throw(f"Cannot reach NextIQ Service at {SERVICE_URL}.",
					 title="Connection Error")
	except requests.exceptions.Timeout:
		frappe.throw("NextIQ Service did not respond in time.", title="Timeout")

	if resp.status_code == 429:
		frappe.throw("Balance check rate limit reached. Please wait a moment.",
					 title="Rate Limited")
	if resp.status_code >= 400:
		frappe.throw(f"NextIQ Service returned error {resp.status_code}.",
					 title="Service Error")

	return resp.json().get("message", {})
