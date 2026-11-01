.DEFAULT_GOAL := help
BASE ?= origin/main
.PHONY: help dev doctor test-fast test test-changed test-contract test-gate coverage check lint typecheck apply-ruleset

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

dev: ## Run the whole local stack: API (8710), web UI (5710) and a demo run; dev token, SQLite .sto/dev.db, no Docker. STO_API_PORT / STO_WEB_PORT override
	uv run python scripts/dev.py

doctor: ## Check Python, uv, Node 24, Docker (optional) and ports; prints a fix for each. Ports: STO_API_PORT, STO_WEB_PORT
	@command -v python3 >/dev/null || { echo "[FAIL] python3 not found"; echo "       fix: install Python 3.12+, e.g. curl -LsSf https://astral.sh/uv/install.sh | sh && uv python install 3.12 --default"; exit 1; }; python3 scripts/doctor.py $(ARGS)

test-fast: ## Hermetic unit tier, no Docker, no network (seconds); contract and gate have their own targets
	uv run pytest -q -m unit

test: ## Run a chosen target: make test T=tests/test_guards.py
	@test -n "$(T)" || { echo "usage: make test T=<path-or-nodeid>"; exit 2; }
	uv run pytest -q $(T)

test-changed: ## Run the direct tests of files changed vs main, within a selection budget (scripts/test_changed.py)
	uv run python scripts/test_changed.py --base $(BASE)

test-contract: ## Contract tier (hermetic)
	uv run pytest -q -m contract

test-gate: ## Gate-integrity tier (hermetic)
	uv run pytest -q -m gate

coverage: ## Hermetic tests with the coverage floor (CI job)
	uv run pytest -q --cov --cov-report=term-missing

check: lint typecheck coverage ## Full local equivalent of CI, for occasional use (not for workers; CI runs it)

lint: ## Ruff lint and format check
	uv run ruff check .
	uv run ruff format --check .

typecheck: ## mypy strict
	uv run mypy

apply-ruleset: ## Create or update the main ruleset from deploy/ruleset-main.json (needs repo admin; run after review)
	@id=$$(gh api repos/{owner}/{repo}/rulesets -q '.[] | select(.name=="main-protection") | .id'); \
	if [ -n "$$id" ]; then gh api -X PUT repos/{owner}/{repo}/rulesets/$$id --input deploy/ruleset-main.json >/dev/null && echo "updated ruleset $$id"; \
	else gh api -X POST repos/{owner}/{repo}/rulesets --input deploy/ruleset-main.json >/dev/null && echo "created ruleset"; fi
