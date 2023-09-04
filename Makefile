.PHONY: check-prereqs format check-format test lint snap snap-install

check-prereqs:
	@printf "%s black\n" $$(which black >/dev/null && echo "[OK]" || echo "[MISSING]")
	@printf "%s snapcraft\n" $$(which snapcraft >/dev/null && echo "[OK]" || echo "[MISSING]")

format:
	black *.py

check-format:
	black --check openstack_charms_cert_validator.py

lint:
	mypy openstack_charms_cert_validator.py

test: check-format lint

snap:
	snapcraft

snap-install:
	sudo snap install ./openstack-charms-cert-validator_*_amd64.snap --dangerous --classic
