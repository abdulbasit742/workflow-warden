PYTHONPATH ?= src

.PHONY: test smoke-scan audit

test:
	PYTHONPATH=$(PYTHONPATH) python -m unittest discover -s tests -v

smoke-scan:
	PYTHONPATH=$(PYTHONPATH) python -m workflow_warden scan tests/fixtures --minimum-severity low --format text

audit:
	PYTHONPATH=$(PYTHONPATH) python -m workflow_warden scan .github/workflows --minimum-severity medium --fail-on medium
