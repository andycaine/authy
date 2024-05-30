SHELL := /bin/bash
STACK_NAME ?= authy

install:
	pip install -r requirements.txt

clean:
	rm -rf .aws-sam
	rm -rf packaged.yaml

.aws-sam/build:
	sam build

packaged.yaml: .aws-sam/build
	sam package \
		--resolve-s3
		--output-template-file $@

publish: packaged.yaml
	sam publish

test:
	pytest
