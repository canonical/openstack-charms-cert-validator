.PHONY: check-prereqs format check-format test develop snap snap-install

check-prereqs:
	@printf "%s black\n" $$(which black >/dev/null && echo "[OK]" || echo "[MISSING]")
	@printf "%s snapcraft\n" $$(which snapcraft >/dev/null && echo "[OK]" || echo "[MISSING]")

format:
	black *.py

check-format:
	black --check *.py

test: check-format

snap:
	snapcraft

snap-install:
	sudo snap install ./openstack-charms-cert-validator_*_amd64.snap --dangerous --classic

venv:
	python -m venv venv

develop: venv
	. venv/bin/activate && pip install -e .
