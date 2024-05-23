PROJECTNAME := $(shell basename "$(PWD)")
include .env
export $(shell sed 's/=.*//' .env)

## proto-lint: Check protobuf rule
.PHONY: proto-lint
proto-lint:
	@buf lint

## proto-gen: Generate golang files based on protobuf
.PHONY: proto-gen
proto-gen:
	@buf generate

## proto-check-breaking: Check protobuf breaking
.PHONY: proto-check-breaking
proto-check-breaking:
	@buf breaking --against '.git#branch=main' --error-format=json | jq .

## proto-clean: Clean the golang files which are generated based on protobuf
.PHONY: proto-clean
proto-clean: 
	@find protos -type f -name "*.go" -delete

## test-go: Test go file and show the coverage
.PHONY: test-go
test-go:
	@go test --coverprofile=coverage.out ./... 
	@go tool cover -html=coverage.out  

## service-build: Build service image
.PHONY: service-build
service-build:
	@docker build --tag ${SERVICE_NAME}:$(shell git rev-parse HEAD) -f ./build/Dockerfile .

.PHONY: service-up
service-up:
	@docker-compose -f ./deployment/compose.yaml --project-directory . up -d

.PHONY: service-down
service-down:
	@docker-compose -f ./deployment/compose.yaml --project-directory . down 

.PHONY: storage-migrate
storage-migrate:
	@migrate -path migrations -database "postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable" up