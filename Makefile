PROJECTNAME := $(shell basename "$(PWD)")
include .env
export $(shell sed 's/=.*//' .env)
## DB
.PHONY: set-psql
set-psql:
	@docker run --name MyPostgres -d -p 5432:5432 \
		-e POSTGRES_DB=$(POSTGRES_DB) \
		-e POSTGRES_USER=$(POSTGRES_USER) \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		--rm postgres:latest

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
