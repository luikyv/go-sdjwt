test:
	@go test ./...

test-coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html="coverage.out" -o coverage.html
	@echo "Total Coverage: `go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+'` %"

lint:
	@golangci-lint run ./...
