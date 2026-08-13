### NextIQ

NextIQ Wrapper App

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch develop
bench install-app nextiq
```

### Getting Started on Frappe Cloud

If you're a NextIQ customer (or want to become one), see the full step-by-step guide with screenshots:

**[NextIQ Installation & Connection Guide](https://niqa-dev.frappe.cloud/docs)**

It covers two paths:

- **New customer** — creating a Frappe Cloud site, installing NextIQ, signing up for a NextIQ Service account, and connecting.
- **Existing customer on the legacy API key** — updating to the latest NextIQ app and switching over to the new sign-in based connection, without losing your scan history or remaining quota.

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/nextiq
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade

### License

mit
