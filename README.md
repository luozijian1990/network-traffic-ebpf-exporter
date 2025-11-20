# eBPF 网络流量导出器 (Network Traffic Exporter)

本项目使用 eBPF 和 TC (Traffic Control) 挂载点来监控网络流量（源 IP、目标 IP、包数、字节数），并将这些指标导出到 Prometheus。

## 开发背景

在现代云原生和分布式系统的运维中，网络流量的可观测性至关重要。尽管我们已有 `node_exporter` 等成熟工具提供主机层面的网络 I/O 监控（如总带宽使用率、包速率），但它们往往缺乏足够的**细粒度**。

- **传统监控的盲区**：`node_exporter` 只能告诉你当前服务器“有多少流量”，却无法回答“流量从哪里来”或“流量到哪里去”。当发生网络异常（如带宽激增）时，运维人员往往难以第一时间定位到具体的来源 IP 或目标 IP。
- **实时诊断的成本**：`iftop`、`nethogs` 等工具虽然提供了极佳的实时流量透视能力，能按 IP 连接展示流量明细，但它们属于命令行工具，需要运维人员**登录服务器**（SSH）才能查看。这种“登录即查看”的模式在面对大规模集群时效率低下，且无法支持历史数据的回溯与告警。

因此，我们需要一种既具备 `iftop` 的“明细可视能力”，又具备 Prometheus 的“持续监控能力”的方案。本项目正是为了解决这一痛点而生：利用 **eBPF** 技术在内核层高效捕获流量明细（源/目 IP），并将其转化为 Prometheus 指标导出，实现**可视化、持久化、细粒度**的网络流量监控。

## 功能特性

- **高性能监控**：基于 eBPF TC Hook，极低开销。
- **多维度指标**：
  - 源 IP (`src_ip`)
  - 目标 IP (`dst_ip`)
  - 流量方向 (`direction`: `inbound`/`outbound`)
  - IP 类型 (`ip_type`: `private`/`public`)
- **Prometheus 集成**：标准 metrics 接口。

## 技术对比：eBPF TC-Hook vs Gopacket/Pcap

在流量观测领域，传统的 `gopacket/pcap` 方式与 `eBPF TC-Hook` 有显著区别：

| 特性 | eBPF TC-Hook | Gopacket / Pcap |
| :--- | :--- | :--- |
| **运行位置** | **内核态 (Kernel Space)**。程序直接在内核网络栈中运行。 | **用户态 (User Space)**。依赖 `libpcap` 将数据包从内核拷贝到用户态。 |
| **性能开销** | **极低**。无需数据包拷贝 (Zero-copy)，无需上下文切换，适合高吞吐场景 (10G/40G+)。 | **较高**。每个数据包都需要从内核拷贝到用户态，涉及大量系统调用和上下文切换，高负载下易丢包。 |
| **可观测性** | **深层可见**。可访问内核数据结构 (sk_buff)，可获取 socket、cgroup 等元数据。 | **仅限数据包**。只能看到原始数据包内容，难以关联到进程或容器上下文。 |
| **处理能力** | **可编程 & 可修改**。不仅能观测，还能修改、丢弃、重定向数据包 (如 Cilium, Katran)。 | **只读**。通常用于被动分析，无法高效地干预流量。 |
| **部署依赖** | 依赖较新的 Linux 内核 (建议 5.x+)。 | 兼容性好，几乎支持所有操作系统。 |

**总结**：对于生产环境的高性能流量监控，**eBPF 是更优的选择**。Pcap 更适合开发调试或低流量下的抓包分析。

## 前置要求

- **Linux 内核**: v4.18+ (建议 v5.8+ 以支持 CO-RE)。
- **工具链**: `clang`, `llvm`, `make`, `bpftool`。
- **Go**: v1.21+。

### 安装依赖

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm make linux-tools-$(uname -r) linux-headers-$(uname -r)
```

**CentOS/RHEL**:
```bash
sudo yum install -y clang llvm make kernel-devel bpftool
```

## 编译构建

1.  **生成 vmlinux.h** (如果不存在):
    ```bash
    make vmlinux.h
    ```

2.  **生成 eBPF构建产物**:
    ```bash
    make generate
    ```

3.  **编译二进制**:
    ```bash
    make build
    ```

## 运行

需要 root 权限运行 (eBPF 要求):

```bash
sudo ./ebpf-traffic-exporter --iface eth0 --addr :9091
```

- `--iface`: 监控的网卡接口 (默认: `eth0`)。
- `--addr`: Prometheus 指标监听地址 (默认: `:9091`)。

## 指标示例

访问 `/metrics`:

```text
network_traffic_bytes_total{direction="inbound",dst_ip="192.168.1.5",ip_type="private",src_ip="1.1.1.1"} 1234
network_traffic_bytes_total{direction="outbound",dst_ip="8.8.8.8",ip_type="public",src_ip="192.168.1.5"} 5678
```
