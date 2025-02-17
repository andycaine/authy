SHELL := /bin/bash
STACK_NAME ?= authy

LAMBDA_DIRS = login_handler logout_handler oidc_handler session_abac_authorizer
PYTHON_FILES = $(shell find $(LAMBDA_DIRS) -name '*.py')
REQUIREMENT_FILES = $(shell find $(LAMBDA_DIRS) -name 'requirements.txt')

FLAG_DIR = .flags
INSTALLED_FLAG = $(FLAG_DIR)/installed
BUILT_FLAG = $(FLAG_DIR)/built

$(FLAG_DIR):
	mkdir -p $@

.venv:
	python3 -m venv .venv

$(INSTALLED_FLAG): $(REQUIREMENT_FILES) .venv $(FLAG_DIR)
	for r in $(REQUIREMENT_FILES); do \
		.venv/bin/pip install -r $$r ; \
	done
	pip install -r requirements/test.txt
	pip install pip-tools
	touch $@

install: $(INSTALLED_FLAG)

clean:
	rm -rf .aws-sam
	rm -rf packaged.yaml
	rm -rf $(FLAG_DIR)

packaged.yaml: $(BUILT_FLAG)
	sam package \
		--resolve-s3
		--output-template-file $@

publish: packaged.yaml
	sam publish

test:
	pytest

upgrade-deps:
	for dir in $(LAMBDA_DIRS); do \
		if [ -f "$$dir/requirements.in" ]; then \
			pip-compile --upgrade --output-file $$dir/requirements.txt $$dir/requirements.in ; \
		fi ; \
	done

sca: $(REQUIREMENT_FILES)
	for r in $(REQUIREMENT_FILES); do \
		trivy fs $$r ; \
	done

scan: $(BUILT_FLAG)
	trivy fs .aws-sam/build

$(BUILT_FLAG): template.yaml $(REQUIREMENT_FILES_FILES) $(PYTHON_FILES) $(FLAG_DIR)
	sam build
	touch $@

build: $(BUILT_FLAG)
