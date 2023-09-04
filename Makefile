.PHONY: check-prereqs format check-format test lint snap snap-install

check-prereqs:
	@printf "%s black\n" $$(which black >/dev/null && echo "[OK]" || echo "[MISSING]")
	@printf "%s snapcraft\n" $$(which snapcraft >/dev/null && echo "[OK]" || echo "[MISSING]")
	@printf "%s coverage\n" $$(which coverage >/dev/null && echo "[OK]" || echo "[MISSING]")
	@printf "%s python\n" $$(which python >/dev/null && echo "[OK]" || echo "[MISSING]")

format:
	black *.py

check-format:
	black --check openstack_charms_cert_validator.py

lint:
	mypy openstack_charms_cert_validator.py

test: check-prereqs check-format lint
	coverage erase
	./tests/func-tests.sh
	coverage html

snap:
	snapcraft

snap-install:
	sudo snap install ./openstack-charms-cert-validator_*_amd64.snap --dangerous --classic
