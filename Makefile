CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all
all: build

.PHONY: build
build: generate
	go build -o ebpf-traffic-exporter cmd/exporter/main.go

.PHONY: generate
generate: vmlinux.h
	go generate ./...

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	rm -f ebpf-traffic-exporter vmlinux.h internal/ebpf/Bpf_bpfel.go internal/ebpf/Bpf_bpfeb.go internal/ebpf/Bpf_bpfel.o internal/ebpf/Bpf_bpfeb.o
