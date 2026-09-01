<div align="center">

# Network Traffic Exporter

基于 eBPF TC 与 Netfilter Conntrack 的主机网络流量 Prometheus Exporter

![Go version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Network](https://img.shields.io/badge/network-IPv4-2E8B57?style=flat-square)
![Metrics](https://img.shields.io/badge/metrics-Prometheus-E6522C?style=flat-square&logo=prometheus&logoColor=white)

[选择版本](#选择版本) · [快速开始](#快速开始) · [指标](#prometheus-指标) · [Grafana](#grafana-dashboard) · [工作原理](#工作原理) · [故障排查](#故障排查)

</div>

按源 IP、目标 IP、流量方向和公网/内网类型持续统计 Linux 主机网络流量，通过 `/metrics` 暴露 Prometheus 指标，帮助定位“流量从哪里来、到哪里去”。

仓库提供两个指标兼容的实现：`main` 使用 eBPF TC 在数据包路径统计，`conntrack` 使用 Netfilter Conntrack 兼容旧版 Linux。两者可以复用相同的 Prometheus 查询和 Grafana Dashboard。

## 选择版本

| 版本 | 适用环境 | 统计方式 | 构建特点 |
| --- | --- | --- | --- |
| **eBPF（`main`）** | 支持 BTF 与 TC eBPF 的现代 Linux，建议内核 5.8+ | 在所选网卡的 TC ingress/egress 按数据包累计 | 需要 clang、LLVM、bpftool、libbpf 头文件和内核 BTF |
| **[Conntrack（`conntrack`）](https://github.com/luozijian1990/network-traffic-ebpf-exporter/tree/conntrack)** | CentOS 7 / Linux 3.10 等旧版端点主机 | Conntrack 周期转储与 `DESTROY` 事件增量统计 | 纯 Go 静态构建，不依赖 eBPF、TC、内核头文件或 CGO |

> [!TIP]
> 新版内核、需要数据包级观测时选择 `main`；旧版内核无法运行当前 eBPF 程序时，使用 [`conntrack` 分支](https://github.com/luozijian1990/network-traffic-ebpf-exporter/tree/conntrack)。

两个版本保持以下核心指标结构：

```text
network_traffic_bytes_total{src_ip,dst_ip,direction,ip_type}
```

## 主要能力

- 以 TC ingress/egress 观察指定网卡的 IPv4 流量。
- 在内核 eBPF Hash Map 中按源 IP、目标 IP 和方向累计字节数。
- 区分 `inbound`、`outbound` 和目标地址的 `private`、`public` 类型。
- Prometheus 抓取时直接读取内核 Map，无需抓包或复制完整数据包到用户态。
- 自带可导入的 Grafana Dashboard，支持总速率、流量类型和 Top IP 分析。
- Release workflow 可同时打包 eBPF 与 Conntrack 两个 Linux/amd64 版本。

## 快速开始

### 1. 准备环境

eBPF 版本需要：

- Linux 内核 4.18+，建议 5.8+；
- 内核提供 `/sys/kernel/btf/vmlinux`；
- Go 1.21 或更高版本；
- clang、LLVM、make、bpftool 和 libbpf 头文件；
- root 权限加载 eBPF 程序并管理 TC qdisc/filter；
- 目标网卡存在并承载 IPv4 流量。

Ubuntu/Debian 可安装以下构建依赖：

```bash
sudo apt-get update
sudo apt-get install -y "linux-tools-$(uname -r)" clang libbpf-dev llvm make
```

> [!NOTE]
> 不满足内核 BTF 或 TC eBPF 条件时，请使用 [`conntrack` 分支](https://github.com/luozijian1990/network-traffic-ebpf-exporter/tree/conntrack)。

### 2. 构建

```bash
git clone https://github.com/luozijian1990/network-traffic-ebpf-exporter.git
cd network-traffic-ebpf-exporter
make build
```

`make build` 会依次：

1. 从 `/sys/kernel/btf/vmlinux` 生成 `vmlinux.h`；
2. 通过 `bpf2go` 将 [`bpf/traffic.c`](bpf/traffic.c) 编译为 Go 可加载对象；
3. 生成 `ebpf-traffic-exporter` 二进制。

如需单独执行构建阶段：

```bash
make vmlinux.h
make generate
make build
```

### 3. 运行

```bash
sudo ./ebpf-traffic-exporter \
  --iface eth0 \
  --addr :9091
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--iface` | `eth0` | 挂载 TC ingress/egress 程序的网络接口 |
| `--addr` | `:9091` | Prometheus HTTP 监听地址 |

确认指标端点：

```bash
curl http://localhost:9091/metrics
```

> [!IMPORTANT]
> `/metrics` 没有内置认证或 TLS。生产环境应通过监听地址、防火墙或反向代理限制访问范围。

程序收到 `SIGINT` 或 `SIGTERM` 时会退出并删除它创建的 ingress/egress filter。

## Prometheus 指标

核心指标是 eBPF 程序加载期间持续累加的计数器：

```text
network_traffic_bytes_total{direction="inbound",dst_ip="192.168.1.5",ip_type="private",src_ip="1.1.1.1"} 1234
network_traffic_bytes_total{direction="outbound",dst_ip="8.8.8.8",ip_type="public",src_ip="192.168.1.5"} 5678
```

| 标签 | 含义 |
| --- | --- |
| `src_ip` | 数据包源 IPv4 地址 |
| `dst_ip` | 数据包目标 IPv4 地址 |
| `direction` | TC ingress 对应 `inbound`，egress 对应 `outbound` |
| `ip_type` | 根据 `dst_ip` 判断的 `private` 或 `public` |

常用 PromQL：

```promql
# 入站/出站总速率
sum by (direction) (rate(network_traffic_bytes_total[1m]))

# 入站流量来源 Top 10
topk(10, sum by (src_ip) (
  rate(network_traffic_bytes_total{direction="inbound"}[1m])
))

# 出站流量目标 Top 10
topk(10, sum by (dst_ip) (
  rate(network_traffic_bytes_total{direction="outbound"}[1m])
))

# 公网与内网流量
sum by (ip_type) (rate(network_traffic_bytes_total[1m]))
```

Prometheus 抓取配置示例：

```yaml
scrape_configs:
  - job_name: network-traffic-exporter
    static_configs:
      - targets: ["server.example.com:9091"]
```

## Grafana Dashboard

将 [`grafana/dashboard.json`](grafana/dashboard.json) 导入 Grafana，并选择对应的 Prometheus 数据源。Dashboard 可直接用于 eBPF 与 Conntrack 两个版本，包含：

- 入站/出站总流量速率；
- 公网与内网流量分布；
- 源 IP 和目标 IP Top 10；
- 按源 IP 查看入站速率；
- 按目标 IP 查看出站速率。

## 工作原理

```mermaid
flowchart LR
    NIC[网络接口] --> TC[TC ingress / egress]
    TC --> BPF[eBPF IPv4 解析与计数]
    BPF --> MAP[BPF Hash Map]
    MAP --> COLLECTOR[Go Prometheus Collector]
    COLLECTOR --> METRICS["/metrics"]
    METRICS --> PROM[Prometheus / Grafana]
```

eBPF 程序挂载到 `--iface` 指定网卡的 TC ingress 和 egress。每个 IPv4 数据包通过 Ethernet/IP 头提取源地址和目标地址，并以 `(src_ip, dst_ip, direction)` 为键更新内核 Hash Map。

Prometheus 抓取 `/metrics` 时，Go Collector 遍历 Map，将累计字节数转换为 `network_traffic_bytes_total`，再根据目标地址补充 `ip_type` 标签。Map 最多保留 `10240` 个聚合键。

## Conntrack 分支

[`conntrack` 分支](https://github.com/luozijian1990/network-traffic-ebpf-exporter/tree/conntrack) 面向无法满足现代 eBPF 条件的旧版 Linux 端点主机，保留与 `main` 相同的核心指标与 Dashboard 兼容性。

它通过独立 Netlink socket 周期转储 IPv4 Conntrack 表，并订阅 `DESTROY` 事件补齐短连接及关闭时的最终流量。首次转储只建立基线，后续按连接计数器差值累加；还提供 `/healthz`、失败重连以及 Conntrack 自监控指标。

```bash
git clone --branch conntrack https://github.com/luozijian1990/network-traffic-ebpf-exporter.git
cd network-traffic-ebpf-exporter
make build
sudo ./conntrack-traffic-exporter --iface eth0
```

> [!NOTE]
> Conntrack 版本的 NAT 映射与字节统计已在目标环境完成实测验证。具体依赖、方向语义、精度边界和健康检查说明请查看该分支的 [README](https://github.com/luozijian1990/network-traffic-ebpf-exporter/tree/conntrack#readme)。

## 实现边界

- 当前两个版本均只导出 IPv4 流量。
- `main` 仅观察 `--iface` 指定的单个网络接口。
- eBPF Map 的 IP 聚合键容量固定为 `10240`，当前没有 LRU 或 Top-N 淘汰。
- TC eBPF 按数据包统计；Conntrack 按连接累计值和事件统计，两者在 NAT、转发、丢包或事件丢失场景下可能存在语义差异。
- `ip_type` 根据 `dst_ip` 判断，而不是根据通信双方共同判断。

## 故障排查

| 现象 | 检查方式 |
| --- | --- |
| 无法生成 `vmlinux.h` | 确认 `/sys/kernel/btf/vmlinux` 存在，并检查内核是否启用 BTF |
| 找不到 `bpf/bpf_helpers.h` | 安装发行版提供的 libbpf 开发头文件，例如 `libbpf-dev` |
| 加载 eBPF 对象时报权限错误 | 使用 root 运行，并检查主机的 BPF 安全策略和 capability 限制 |
| TC 挂载失败 | 用 `ip link show` 确认 `--iface`，再检查 `tc qdisc show dev <iface>` 和 `tc filter show dev <iface> ingress` |
| `/metrics` 中没有流量指标 | 确认目标接口存在 IPv4 流量，并检查程序是否成功打印两个 TC 挂载日志 |
| Prometheus 无法抓取 | 检查 `--addr`、监听端口、防火墙和 Prometheus target 状态 |

## Release

仓库的 GitHub Actions Release workflow 会分别固定 `main` 与 `conntrack` 的源代码 SHA，并生成：

```text
network-traffic-ebpf-exporter_<version>_linux_amd64.tar.gz
network-traffic-conntrack-exporter_<version>_linux_amd64.tar.gz
SHA256SUMS
release-manifest.json
```

发布产物可从 [GitHub Releases](https://github.com/luozijian1990/network-traffic-ebpf-exporter/releases) 下载。`release-manifest.json` 记录两个版本使用的准确 commit，`SHA256SUMS` 用于校验下载内容。

## 开发与验证

```bash
make generate
go vet ./...
go test ./...
make build
```

清理生成文件与本地二进制：

```bash
make clean
```
