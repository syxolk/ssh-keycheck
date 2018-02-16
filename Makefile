VERSION = $(shell git describe --always --long --dirty)

ssh-keycheck: main.go
	go build -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: test
test:
	go test -v -cover

.PHONY: lint
lint:
	gofmt -l -e . && \
	go vet -all . && \
	gocyclo -over 15 . && \
	golint -set_exit_status && \
	ineffassign . && \
	misspell -error .


.PHONY: clean
clean:
	go clean
