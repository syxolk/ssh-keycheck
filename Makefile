VERSION = $(shell git describe --always --long --dirty)

ssh-keycheck: main.go
	go build -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: clean
clean:
	rm ssh-keycheck
