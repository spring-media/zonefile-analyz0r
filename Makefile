SHELL := bash

.PHONY: build
build:
	docker build -t zone .

.PHONY: csv
csv:
	@echo "+ $@"
	@rm -f dist/check.csv
	@docker run -v `pwd`/dist:/root/.analyzor/dist -it zone csv

.PHONY: console
console:
	@echo "+ $@"
	@rm -f dist/check.csv
	@docker run -it zone console