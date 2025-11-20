CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all
all: build

.PHONY: build
build: generate
	go build -o ebpf-traffic-exporter .

.PHONY: generate
generate: vmlinux.h
	go generate ./...

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	rm -f ebpf-traffic-exporter vmlinux.h bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
