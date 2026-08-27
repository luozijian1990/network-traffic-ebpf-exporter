.PHONY: all build test clean
all: build

build:
	CGO_ENABLED=0 go build -o conntrack-traffic-exporter ./cmd/exporter

test:
	go test ./...

clean:
	rm -f conntrack-traffic-exporter
