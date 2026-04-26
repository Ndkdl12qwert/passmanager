SHELL := /usr/bin/env bash

.PHONY: all build test integration docs clean release

all: build

build:
	./build_all.sh

test:
	go test ./pkg/...
	./tests/run_tests.shell

integration:
	./tests/integration.sh

docs:
	@echo "Documentation files:"
	@find docs -maxdepth 1 -type f | sort

release:
	./release --clean

clean:
	rm -f bin/passmanager bin/pass
	rm -rf release/