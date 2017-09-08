VERSION = $(shell git describe --always --long --dirty)

ssh-keycheck: main.go
	go build -ldflags="-X main.version=$(VERSION)"

.PHONY: clean
clean:
	rm ssh-keycheck
