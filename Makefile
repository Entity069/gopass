.PHONY: build run test check coverage docker docker-test smoke

build:
	go build -trimpath -o bin/cli-login ./cmd/login

run:
	go run ./cmd/login

test:
	go test -race -count=1 ./...

check:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)
	go vet ./...
	go test -race -count=1 ./...
	go mod verify

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

docker:
	docker compose build
	docker compose run --rm login

docker-test:
	docker build --target test -t cli-login:test .

smoke: build
	python3 scripts/smoke.py ./bin/cli-login
