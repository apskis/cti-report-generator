# Contributing

Thanks for working on the CTI Report Generator. This guide covers local setup,
the checks CI enforces, and a few project conventions.

## Local setup

```bash
python -m venv .venv && source .venv/bin/activate   # Python 3.11+
pip install -r requirements.txt -r requirements-dev.txt
```

Copy `local.settings.json.template` to `local.settings.json` and fill in your
Key Vault URL and enabled collectors. Secrets themselves live in Azure Key
Vault, not in the repo.

## Checks (must pass before pushing)

CI (`.github/workflows/ci.yml`) runs these on every PR; run them locally first:

```bash
ruff check .            # lint
ruff format --check .   # formatting
pytest                  # tests (with coverage)
```

`ruff format .` and `ruff check --fix .` apply the autofixes.

## Dependencies

Dependencies are managed with [pip-tools]. Edit the **`.in`** files, never the
locked `.txt` files directly, then regenerate the locks:

```bash
pip-compile --generate-hashes requirements.in
pip-compile --generate-hashes --allow-unsafe -c requirements.txt requirements-dev.in
```

## Project layout

- `function_app.py` — Azure Functions entry point (HTTP + timer triggers).
- `src/` — application code: `collectors/`, `agents/`, `reports/`, `gates/`,
  `core/`, `enrichment/`, `validation/`, `utils/`.
- `tests/` — the pytest suite (this is what CI runs).
- `scripts/` — manual/dev utilities (not collected by pytest).
- `config/` — collector, feature, OSINT, and customer-profile YAML.
- `docs/` — documentation (`docs/audits/` holds point-in-time audit outputs).
- `assets/` — report banner, template `.docx`, and template spec.

## Conventions

- New data sources are added as a collector under `src/collectors/` and
  registered in `src/collectors/registry.py`.
- Organization-specific values (name, brand color, contact, products) come from
  `config/customer_profile.yaml` via `src.core.config.customer_profile` — don't
  hardcode them.
- Keep tests alongside the code they cover in `tests/`, and update fixtures when
  a data contract changes.
