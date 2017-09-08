VERSION = $(shell git describe --always --long --dirty)

ssh-keycheck: main.go
	go build -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: test
test:
	go test -v

.PHONY: clean
clean:
	rm ssh-keycheck
