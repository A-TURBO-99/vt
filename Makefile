.PHONY: build test fmt

build:
	go build -o vt ./cmd/vt

test:
	go test ./...

fmt:
	gofmt -w .
