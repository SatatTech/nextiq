frappe.provide("nextiq");

nextiq.show_update_notifications = function () {
	const info = frappe.boot.nextiq_update;

	if (!info || !frappe.user_roles || !frappe.user_roles.includes("System Manager")) {
		return;
	}

	if (info.mandatory && info.min_version) {
		nextiq._show_banner(info);
	} else {
		nextiq._hide_banner();
	}
};

nextiq._show_banner = function (info) {
	const banner_id = "nextiq-mandatory-update-banner";
	if (document.getElementById(banner_id)) return;

	$(`<div id="${banner_id}">
		<strong>NextIQ Update Required</strong>
		&nbsp;
		v${info.min_version} required, v${info.current_version} installed. Please update the NextIQ app.
	</div>`).css({
		background:   "#fff3cd",
		borderBottom: "1px solid #e8a838",
		padding:      "7px 20px",
		textAlign:    "center",
		fontSize:     "13px",
		lineHeight:   "1.5",
		zIndex:       "1050",
	}).insertBefore(".navbar");
};

nextiq._hide_banner = function () {
	$("#nextiq-mandatory-update-banner").remove();
};

// Runs once per session on first page-change after boot
$(document).on("page-change", function () {
	if (frappe._nextiq_notifications_shown) return;
	frappe._nextiq_notifications_shown = true;
	setTimeout(nextiq.show_update_notifications, 1500);
});
