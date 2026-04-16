# Copyright (c) 2026, krushang.patel@satat.tech and contributors
# For license information, please see license.txt

import base64
import traceback

import frappe
import requests


# ── Public endpoints (called from card-scan portal JS) ───────────────────────

@frappe.whitelist()
def submit_card_scan(merged_image_base64, filename="business_card.jpg"):
	"""
	Receive merged business card image from the portal, save it locally,
	and enqueue a background job that calls NextIQ Service.

	Returns: {"log_name": str}
	"""
	# Strip data URL prefix if the browser included it
	if "," in merged_image_base64:
		merged_image_base64 = merged_image_base64.split(",")[1]

	log = frappe.get_doc({
		"doctype": "Card Scan Log",
		"status": "Pending",
		"submitted_at": frappe.utils.now(),
	})
	log.insert(ignore_permissions=True)
	frappe.db.commit()

	# Save the merged image as a Frappe file attachment
	try:
		file_content = base64.b64decode(merged_image_base64)
		file_doc = frappe.get_doc({
			"doctype": "File",
			"file_name": f"card_scan_{log.name}.jpg",
			"content": file_content,
			"is_private": 0,
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

	frappe.enqueue(
		"nextiq.api._process_scan_bg",
		log_name=log.name,
		queue="long",
		timeout=180,
		now=False,
	)

	return {"log_name": log.name}


@frappe.whitelist()
def get_card_scan_status(log_name):
	"""Poll status of a Card Scan Log (used by the portal for live updates)."""
	if not frappe.db.exists("Card Scan Log", log_name):
		frappe.throw(f"Card Scan Log '{log_name}' not found", frappe.DoesNotExistError)

	return frappe.db.get_value(
		"Card Scan Log", log_name,
		["status", "lead", "error_message", "scans_remaining"],
		as_dict=True,
	)


# ── Background job ────────────────────────────────────────────────────────────

def _process_scan_bg(log_name):
	"""
	Background job: load image, call NextIQ Service, create Lead, update log.
	"""
	logger = frappe.logger("nextiq")
	logger.info(f"[NextIQ BG] Starting scan: {log_name}")

	try:
		frappe.db.set_value("Card Scan Log", log_name, "status", "Processing")
		frappe.db.commit()

		# ── Load settings ──
		settings = frappe.get_single("NextIQ Settings")
		if not settings.service_url or not settings.api_key:
			raise Exception("NextIQ Settings not configured. Please set Service URL and API Key.")

		service_url = settings.service_url.rstrip("/")
		api_key = settings.api_key

		# ── Load image ──
		log = frappe.get_doc("Card Scan Log", log_name)
		if not log.merged_image:
			raise Exception("No image attached to this log.")

		file_doc = frappe.get_doc("File", {"file_url": log.merged_image})
		image_base64 = base64.b64encode(file_doc.get_content()).decode()

		logger.info(f"[NextIQ BG] Calling service at {service_url}")

		# ── Call NextIQ Service ──
		try:
			response = requests.post(
				f"{service_url}/api/method/nextiq_service.api.process_scan",
				json={
					"api_key": api_key,
					"image_base64": image_base64,
					"filename": "business_card.jpg",
				},
				headers={"Content-Type": "application/json"},
				timeout=150,
			)
		except requests.exceptions.ConnectionError:
			# Service is unreachable — count NOT charged
			raise Exception(
				f"Cannot reach NextIQ Service at {service_url}. "
				"Please check the Service URL in NextIQ Settings."
			)
		except requests.exceptions.Timeout:
			# Service took too long — count NOT charged
			raise Exception(
				"NextIQ Service did not respond in time. "
				"The service may be overloaded. Please try again."
			)

		# Handle HTTP error codes explicitly so the message is user-friendly
		# In all cases below the service never completed processing, so count is NOT charged
		if response.status_code == 503:
			raise Exception(
				"NextIQ Service is temporarily unavailable (503). "
				"Scan was not charged. Please try again in a moment."
			)
		elif response.status_code == 502:
			raise Exception(
				"NextIQ Service returned a bad gateway error (502). "
				"Scan was not charged. Please try again."
			)
		elif response.status_code >= 500:
			raise Exception(
				f"NextIQ Service returned a server error ({response.status_code}). "
				"Scan was not charged. Please try again."
			)
		elif response.status_code == 401 or response.status_code == 403:
			raise Exception(
				f"NextIQ Service rejected the request ({response.status_code}). "
				"Please verify your API Key in NextIQ Settings."
			)
		elif response.status_code >= 400:
			raise Exception(
				f"NextIQ Service returned error {response.status_code}. "
				"Scan was not charged."
			)

		# Frappe wraps whitelisted function responses in {"message": ...}
		result = response.json().get("message", {})
		logger.info(f"[NextIQ BG] Service response success={result.get('success')}")

		if not result.get("success"):
			error_code = result.get("error", "unknown")
			error_msg = result.get("message", "Service returned an error.")

			if error_code == "quota_exceeded":
				status = "Quota Exceeded"
			elif error_code == "not_a_business_card":
				status = "Invalid Image"
			else:
				status = "Failed"

			frappe.db.set_value("Card Scan Log", log_name, {
				"status": status,
				"error_message": error_msg,
				"scans_remaining": result.get("scans_remaining"),
				"processed_at": frappe.utils.now(),
			})
			frappe.db.commit()
			return

		# ── Create Lead ──
		lead_data = result.get("data", {})
		if lead_data:
			lead = frappe.get_doc({"doctype": "Lead", **lead_data})
			lead.insert(ignore_permissions=True)
			frappe.db.commit()
			lead_name = lead.name
			logger.info(f"[NextIQ BG] Lead created: {lead_name}")
		else:
			lead_name = None
			logger.warning(f"[NextIQ BG] Service returned no lead data for {log_name}")

		frappe.db.set_value("Card Scan Log", log_name, {
			"status": "Success",
			"lead": lead_name,
			"scans_remaining": result.get("scans_remaining"),
			"processed_at": frappe.utils.now(),
			"ai_response": frappe.as_json(result.get("data", {})),
		})
		frappe.db.commit()

	except Exception as e:
		logger.error(f"[NextIQ BG] Failed for {log_name}: {e}\n{traceback.format_exc()}")
		frappe.log_error(traceback.format_exc(), f"NextIQ: Card Scan Failed: {log_name}")
		frappe.db.set_value("Card Scan Log", log_name, {
			"status": "Failed",
			"error_message": str(e)[:1000],
			"processed_at": frappe.utils.now(),
		})
		frappe.db.commit()
