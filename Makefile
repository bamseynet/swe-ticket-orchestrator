.DEFAULT_GOAL := help
.PHONY: help test-fast test test-changed lint typecheck

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

test-fast: ## Hermetic unit tests, no Docker, no network (seconds)
	uv run pytest -q

test: ## Run a chosen target: make test T=tests/test_guards.py
	@test -n "$(T)" || { echo "usage: make test T=<path-or-nodeid>"; exit 2; }
	uv run pytest -q $(T)

test-changed: ## Run the direct tests of files changed vs main (D0-08 refines selection)
	@files=$$( { git diff --name-only origin/main...HEAD; git diff --name-only HEAD; git ls-files -o --exclude-standard; } 2>/dev/null \
	  | sed -n -e 's|^src/sto/\(.*\)\.py$$|tests/\1|p' -e 's|^\(tests/.*test_.*\.py\)$$|\1|p' | sort -u ); \
	targets=""; for f in $$files; do \
	  if [ -f "$$f" ]; then targets="$$targets $$f"; \
	  else d=$$(dirname $$f); b=$$(basename $$f); \
	    [ -f "$$d/test_$$b.py" ] && targets="$$targets $$d/test_$$b.py"; \
	    [ -d "$$f" ] && targets="$$targets $$f"; fi; done; \
	if [ -z "$$targets" ]; then echo "test-changed: no direct tests for the changed files"; \
	else uv run pytest -q $$targets; fi

lint: ## Ruff lint and format check
	uv run ruff check src tests
	uv run ruff format --check src tests

typecheck: ## mypy strict
	uv run mypy
