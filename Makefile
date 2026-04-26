SHELL := /usr/bin/env bash

.PHONY: all build test integration docs clean
all: build

build:
	./build_all.sh

test:
	go test ./pkg/...


integration:
	chmod +x ./tests/run_tests.sh ./tests/integration.sh
	./tests/run_tests.sh
	./tests/integration.sh

docs:
	@echo "Documentation files:"
	@find docs -maxdepth 1 -type f | sort

clean:
	rm -f bin/passman bin/pass

