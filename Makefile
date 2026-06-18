.PHONY: help test validate

help:
	@printf '%s\n' "Targets:" \
		"  make test      Run the test suite" \
		"  make validate  Run skills validation"

test:
	uv run --with-requirements requirements-test.txt \
		python -m unittest discover -s tests -p 'test_*.py'

validate:
	python3 scripts/validate_skills.py
