# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import base64
import hashlib
import hmac
import ipaddress
import secrets
import traceback
import urllib.parse

import frappe
import requests

# Fields allowed when creating a Lead from scan data — mirrors the service-side list
_ALLOWED_LEAD_FIELDS = frozenset({
	"salutation", "first_name", "middle_name", "last_name",
	"gender", "job_title", "email_id", "mobile_no", "whatsapp_no",
	"phone", "phone_ext", "company_name", "website",
	"fax", "city", "state", "country",
})
_MAX_FIELD_LEN = 500   # max characters per Lead field value


# ── Helpers ──────────────────────────────────────────────────────────────────

_BLOCKED_HOSTS = frozenset({"metadata.google.internal", "169.254.169.254"})


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


def _validate_service_url(url):
	"""
	Block private/loopback IP targets in NextIQ Settings.service_url.
	Returns an error string, or None if the URL is acceptable.
	"""
	try:
		parsed = urllib.parse.urlparse(url)
	except Exception:
		return "service_url could not be parsed."
	if parsed.scheme not in ("http", "https"):
		return "service_url must be http or https."
	hostname = (parsed.hostname or "").lower()
	if hostname in _BLOCKED_HOSTS:
		return f"service_url hostname '{hostname}' is not permitted."
	try:
		ip = ipaddress.ip_address(hostname)
		if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
			return "service_url must not point to a private or internal address."
	except ValueError:
		pass  # domain name — fine
	return None


# ── Public endpoints (called from card-scan portal JS) ───────────────────────

@frappe.whitelist()
def submit_card_scan(merged_image_base64, filename="business_card.jpg"):
	"""
	Receive merged business card image from the portal.
	Generates job_id + cb_secret, saves image, enqueues _fire_scan_to_service.

	Returns immediately: {"log_name": str}
	The browser can close after this — Lead is created via background + callback.
	"""
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

	log_name = frappe.db.get_value("Card Scan Log", {"job_id": job_id}, "name")
	if not log_name:
		return {"success": False, "error": "invalid_job_id"}

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
			try:
				lead = frappe.get_doc({"doctype": "Lead", **data})
				lead.insert(ignore_permissions=True)
				frappe.db.commit()
				lead_name = lead.name
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
				# AI processed successfully and returned data, but the data has
				# values that Frappe cannot accept (e.g. country="USA" instead of
				# "United States", invalid select option, bad link value, etc.).
				# Scan is already charged — this is a data quality issue, not a failure.
				err_msg = str(e)[:500] or "AI data could not be saved as a Lead — one or more field values were invalid."
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
		if not settings.service_url or not settings.api_key:
			raise Exception("NextIQ Settings not configured. Please set Service URL and API Key.")

		service_url = settings.service_url.rstrip("/")
		api_key     = settings.get_password("api_key")

		# ── Validate service_url (SSRF + HTTP warning) ────────────────────────
		url_err = _validate_service_url(service_url)
		if url_err:
			raise Exception(f"NextIQ Settings: invalid service_url — {url_err}")
		if service_url.startswith("http://"):
			logger.warning(
				"[NextIQ] service_url uses plain HTTP — data is unencrypted in transit. "
				"Use HTTPS in production."
			)

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

		logger.info(f"[NextIQ] Calling service at {service_url}, job_id={log.job_id}")

		try:
			response = requests.post(
				f"{service_url}/api/method/nextiq_service.api.process_scan",
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
				},
				timeout=15,  # service should accept in <1s — short timeout
			)
		except requests.exceptions.ConnectionError:
			raise Exception(
				f"Cannot reach NextIQ Service at {service_url}. "
				"Please check the Service URL in NextIQ Settings."
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
		if not settings.service_url or not settings.api_key:
			return

		service_url = settings.service_url.rstrip("/")
		api_key     = settings.get_password("api_key")

		url_err = _validate_service_url(service_url)
		if url_err:
			frappe.log_error(f"Feedback skipped — invalid service_url: {url_err}",
							 f"NextIQ: Feedback Send Failed: {log_name}")
			return

		requests.post(
			f"{service_url}/api/method/nextiq_service.api.receive_scan_feedback",
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

		site_url = frappe.utils.get_url()

		if outcome == "success" and lead_name:
			lead_url = f"{site_url}/app/lead/{lead_name}"
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Lead created from your card scan",
				message=(
					f"<p>Your card scan is complete.</p>"
					f"<p><strong>Lead created:</strong> "
					f"<a href='{lead_url}'>{lead_name}</a></p>"
					+ (f"<p><strong>Scans remaining:</strong> {scans_remaining}</p>"
					   if scans_remaining is not None else "")
				),
				delayed=False,
			)

		elif outcome == "not_a_business_card":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Card scan — image not recognised",
				message=(
					"<p>Your card scan could not extract contact information from the image. "
					"1 scan was used.</p>"
					+ (f"<p><strong>{scans_remaining} scan(s) remaining.</strong></p>"
					   if scans_remaining is not None else "")
					+ "<p>Please try again with a clearer image of a business card.</p>"
				),
				delayed=False,
			)

		elif outcome == "quota_exceeded":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Scan quota exhausted",
				message=(
					"<p>Your scan quota is exhausted. No more scans can be processed.</p>"
					"<p>Please contact the NextIQ team to increase your quota.</p>"
				),
				delayed=False,
			)

		elif outcome == "invalid_data":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Card scan — data could not be saved",
				message=(
					"<p>Your card scan completed and the AI extracted data, but one or more "
					"field values could not be saved as a Lead (e.g. an unrecognised country "
					"name or invalid option).</p>"
					"<p><strong>1 scan was used.</strong></p>"
					+ (f"<p><strong>Details:</strong> {message}</p>" if message else "")
					+ "<p>Please open the Card Scan Log to review the AI response and "
					"create the Lead manually.</p>"
				),
				delayed=False,
			)

		elif outcome == "duplicate_lead":
			frappe.sendmail(
				recipients=[user_email],
				subject="[NextIQ] Card scan — lead already exists",
				message=(
					"<p>Your card scan completed, but a lead with this email address already exists in the system.</p>"
					+ (f"<p><strong>Details:</strong> {message}</p>" if message else "")
					+ "<p>Please check your existing leads or update the contact details on the card.</p>"
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
	if not settings.service_url or not settings.api_key:
		frappe.throw("NextIQ Settings not configured (Service URL or API Key missing).",
					 title="Not Configured")

	service_url = settings.service_url.rstrip("/")
	api_key     = settings.get_password("api_key")

	try:
		resp = requests.get(
			f"{service_url}/api/method/nextiq_service.api.check_quota",
			headers={
				"X-NextIQ-API-Key": api_key,
				"Content-Type":     "application/json",
			},
			timeout=10,
		)
	except requests.exceptions.ConnectionError:
		frappe.throw(f"Cannot reach NextIQ Service at {service_url}.",
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
