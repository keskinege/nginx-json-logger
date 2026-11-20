COMPOSE := docker compose -f test/e2e/docker-compose.yml

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v

unit:
	node test/unit/run-node.mjs

unit-nginx: up
	@sleep 1
	@curl -sS localhost:8088/__unit | tee /tmp/jsonlog-unit.json | jq .
	@jq -e '.failed == 0' /tmp/jsonlog-unit.json >/dev/null || (echo "unit tests failed"; exit 1)

contract: unit
	@node test/unit/sample.mjs | tee /tmp/jsonlog-sample.json | jq -e -f test/e2e/contract.jq >/dev/null
	@jq -e . /tmp/jsonlog-sample.json >/dev/null
	@echo "contract OK"

check: unit contract

e2e:
	./test/e2e/run.sh

logs:
	tail -n 20 logs/json.log

.PHONY: up down unit unit-nginx contract check e2e logs
