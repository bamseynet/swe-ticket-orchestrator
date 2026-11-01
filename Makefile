.DEFAULT_GOAL := help
BASE ?= origin/main
.PHONY: help doctor test-fast test test-changed lint typecheck apply-ruleset

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

doctor: ## Check Python, uv, Node 24, Docker (optional) and ports; prints a fix for each. Ports: STO_API_PORT, STO_WEB_PORT
	@command -v python3 >/dev/null || { echo "[FAIL] python3 not found"; echo "       fix: install Python 3.12+, e.g. curl -LsSf https://astral.sh/uv/install.sh | sh && uv python install 3.12"; exit 1; }; python3 scripts/doctor.py $(ARGS)

test-fast: ## Hermetic unit tests, no Docker, no network (seconds)
	uv run pytest -q

test: ## Run a chosen target: make test T=tests/test_guards.py
	@test -n "$(T)" || { echo "usage: make test T=<path-or-nodeid>"; exit 2; }
	uv run pytest -q $(T)

test-changed: ## Run the direct tests of files changed vs main (D0-08 refines selection)
	@targets=$$( { git diff --name-only $(BASE)...HEAD; git diff --name-only HEAD; git ls-files -o --exclude-standard; } 2>/dev/null | sort -u | while read -r f; do \
	  case "$$f" in \
	    tests/conftest.py|tests/*/conftest.py) echo "$$(dirname "$$f")";; \
	    tests/*.py|tools/*/test_*.py|tools/test_*.py) echo "$$f";; \
	    src/sto/*.py) r=$${f#src/sto/}; echo "tests/$$(dirname "$$r")/test_$$(basename "$$r")"; echo "tests/$${r%.py}";; \
	    tools/*.py) echo "$$(dirname "$$f")/test_$$(basename "$$f")";; \
	  esac; done | sort -u | while read -r t; do [ -e "$$t" ] && echo "$$t"; done ); \
	if [ -z "$$targets" ]; then echo "test-changed: no direct tests for the changed files"; \
	else uv run pytest -q $$targets; fi

lint: ## Ruff lint and format check
	uv run ruff check .
	uv run ruff format --check .

typecheck: ## mypy strict
	uv run mypy

apply-ruleset: ## Create or update the main ruleset from deploy/ruleset-main.json (needs repo admin; run after review)
	@id=$$(gh api repos/{owner}/{repo}/rulesets -q '.[] | select(.name=="main-protection") | .id'); \
	if [ -n "$$id" ]; then gh api -X PUT repos/{owner}/{repo}/rulesets/$$id --input deploy/ruleset-main.json >/dev/null && echo "updated ruleset $$id"; \
	else gh api -X POST repos/{owner}/{repo}/rulesets --input deploy/ruleset-main.json >/dev/null && echo "created ruleset"; fi
