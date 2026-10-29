IMAGE ?= zday-protocol-sandbox:latest
.DEFAULT_GOAL := run

.PHONY: up down run sandbox-image test docker-test
up:                   ## everything in Docker (dashboard + sandbox) -> http://127.0.0.1:8000
	docker compose up --build -d
down:
	docker compose down
run:                  ## dashboard on the host, every attack in its own container -> http://127.0.0.1:8000
	./scripts/run-docker-sandbox.sh
sandbox-image:        ## (re)build the per-attack sandbox image
	docker build -f Dockerfile.sandbox -t $(IMAGE) .
test:                 ## no Docker needed (a stand-in docker command verifies every hardening flag)
	python3 selftest.py && python3 test_docker_backend.py && node test_analyzer.js
docker-test: sandbox-image  ## real Docker: full scan -> attack -> fix -> re-attack through containers
	LD_SANDBOX=docker python3 selftest.py
