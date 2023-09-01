
format:
	black *.py

venv:
	python -m venv venv

develop: venv
	. venv/bin/activate && pip install -e .
