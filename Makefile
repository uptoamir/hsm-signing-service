.PHONY: build test clippy dev-token run run-mock self-test bench docker up down secrets

build:
	cargo build --release

test:
	cargo test

clippy:
	cargo clippy --all-targets -- -D warnings

dev-token:
	./scripts/dev-token.sh > /dev/null

run: dev-token
	set -a; . ./.softhsm/env.sh; set +a; cargo run --release -- serve --log-format pretty

run-mock:
	cargo run --release -- --backend mock --log-format pretty serve

self-test: dev-token
	set -a; . ./.softhsm/env.sh; set +a; cargo run --release -- self-test

bench:
	mkdir -p bench-results
	cargo run --release --bin hsm-bench -- --url http://127.0.0.1:8080 --markdown bench-results/latest.md --json bench-results/latest.json

secrets:
	mkdir -p secrets
	test -f secrets/user_pin.txt || openssl rand -hex 16 > secrets/user_pin.txt
	test -f secrets/so_pin.txt || openssl rand -hex 16 > secrets/so_pin.txt
	chmod 600 secrets/*.txt

docker:
	docker build -t arkion/hsm-signer:local .

up: secrets
	docker compose up --build

down:
	docker compose down -v
