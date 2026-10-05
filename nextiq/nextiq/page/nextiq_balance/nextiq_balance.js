frappe.pages["nextiq-balance"].on_page_load = function (wrapper) {
	const page = frappe.ui.make_app_page({
		parent: wrapper,
		title: __("NextIQ Balance"),
		single_column: true,
	});

	new nextiq.BalanceView(page);
};

frappe.provide("nextiq");

nextiq.BalanceView = class BalanceView {
	constructor(page) {
		this.page = page;
		this.$body = $('<div style="max-width: 420px; margin: 24px auto;">').appendTo(page.body);
		this.page.set_primary_action(__("Refresh"), () => this.load(), "refresh");
		this.load();
	}

	async load() {
		this.$body.html(`<p class="text-muted">${__("Loading...")}</p>`);
		try {
			const data = await frappe.xcall("nextiq.api.get_live_balance");
			if (!data || data.success === false) {
				this.render_error(
					(data && data.message) || __("Could not fetch your balance right now.")
				);
				return;
			}
			this.render(data);
		} catch (e) {
			this.render_error(
				(e && e.message) ||
					__("Could not fetch your balance. Make sure NextIQ Settings is connected.")
			);
		}
	}

	render(data) {
		const allowed = data.scans_allowed || 0;
		const used = data.scans_used || 0;
		const remaining =
			data.scans_remaining != null ? data.scans_remaining : Math.max(allowed - used, 0);
		const pct = allowed > 0 ? Math.min(100, Math.round((used / allowed) * 100)) : 0;
		const low = allowed > 0 && remaining <= Math.max(1, Math.round(allowed * 0.1));

		this.$body.html(`
			<div class="frappe-card" style="padding: 20px;">
				<div style="font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em;">
					${__("Account")}
				</div>
				<div style="font-size: 14px; margin-bottom: 16px;">
					${frappe.utils.escape_html(data.customer || "")}
				</div>
				<div style="font-size: 40px; font-weight: 600; line-height: 1;">${remaining}</div>
				<div style="color: var(--text-muted); margin-top: 4px;">
					${__("scans remaining of {0}", [allowed])}
				</div>
				<div class="progress" style="height: 8px; margin-top: 16px;">
					<div class="progress-bar${low ? " progress-bar-danger" : ""}" style="width: ${pct}%;"></div>
				</div>
				<div style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">
					${__("{0} used", [used])} &middot; ${__("status")}: ${frappe.utils.escape_html(data.status || "")}
				</div>
				${
					low
						? `<div class="alert alert-warning" style="margin-top: 16px;">${__(
								"Running low on scans. Contact your NextIQ account manager to top up."
						  )}</div>`
						: ""
				}
			</div>
		`);
	}

	render_error(msg) {
		this.$body.html(`<div class="alert alert-warning">${frappe.utils.escape_html(msg)}</div>`);
	}
};
