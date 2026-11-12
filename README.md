# Proxy

Proxy 是用于 Linux 与 Windows 的透明代理与网络转发工具，支持 IPv4/IPv6 双栈流量接管、规则分流、DNS 解析与系统服务常驻。Linux 使用 nftables TPROXY 与 cgroup v2 防回环；Windows 使用 WinDivert 驱动捕获网络报文并通过 SCM 管理服务。两个平台保持配置与命令行行为一致。

## 目录

- [特性](#特性)
- [工作原理](#工作原理)
  - [Linux 透明接管（TPROXY + cgroup v2）](#linux-透明接管tproxy--cgroup-v2)
  - [Windows 透明接管（WinDivert）](#windows-透明接管windivert)
  - [DNS 解析与依赖检查](#dns-解析与依赖检查)
  - [分流与出站](#分流与出站)
- [快速上手](#快速上手)
  - [环境要求](#环境要求)
  - [编译构建](#编译构建)
  - [运行与测试](#运行与测试)
- [配置说明](#配置说明)
  - [全局配置示例（global.yaml）](#全局配置示例globalyaml)
  - [DNS 规则语法](#dns-规则语法)
  - [字段参考与默认值](#字段参考与默认值)
- [命令行（CLI）参考](#命令行cli参考)
  - [管理命令](#管理命令)
  - [状态与监控](#状态与监控)
  - [DNS 与 Geo 数据库](#dns-与-geo-数据库)
  - [接管状态与抓包](#接管状态与抓包)
- [系统服务](#系统服务)
  - [Linux（systemd）](#linuxsystemd)
  - [Windows（SCM）](#windowsscm)
- [测试与验证](#测试与验证)
  - [测试脚本](#测试脚本)
  - [平台状态与注意事项](#平台状态与注意事项)
- [开发规范](#开发规范)

## 特性

- 流量接管：支持 TCP 与 UDP 双栈捕获（可指定 CIDR 和端口范围），支持 53 端口 DNS 劫持。提供全局模式（`scope: global`）、网关模式（`scope: gateway`）与 Windows 单应用模式（`scope: application`）。
- 本地上游防回环：Linux 通过 cgroup v2 与 `ss --cgroup` 识别本地 SOCKS5/HTTP 上游服务或 Docker 容器并豁免其出站；Windows 根据监听端点 PID 过滤放行，支持 `exclude_applications` 进程路径白名单。
- DNS 引擎：支持 `udp`、`tcp`、`doh`、`doh3`、`dot`、`doq` 与 `system` 上游。支持 `domain`、`domain_suffix` 与 `geosite` 规则分流。包含配置期与运行期依赖循环检测，内置内存缓存。
- 出站与路由：出站支持 `direct`、`socks5`（含 UDP ASSOCIATE）与 `http`。路由规则支持按 `cidr`、`geoip`、`port` 与 `network` 匹配。
- 运维与状态：支持配置热重载（`proxy reload`），进程退出时自动清理路由与防火墙规则，内置内存日志缓冲区（`proxy logs -f`）。

## 工作原理

### Linux 透明接管（TPROXY + cgroup v2）

- 接管链路：
  - 本机出站（OUTPUT）：本地出站流量通过 nftables 打上 `fwmark`，策略路由（路由表 100，优先级 11000）将流量重定向至回环接口 `lo`。
  - 预路由入站（PREROUTING）：`lo` 或指定入口网卡（网关模式）上的带标流量通过内核 TPROXY 模块分发给本地接管端口（默认 `15080`），保留原始源地址与目的地址。
- 上游防回环：
  - 本机全局模式以专用非 root 用户 `proxyd` 运行，代理进程自身的 UID 流量直接跳过。
  - 守护进程每 500ms 检查本地 SOCKS5/HTTP 上游所属的 cgroup v2。上游属于独立 systemd 服务或 Docker 容器时，在 OUTPUT 链打标前予以豁免，避免代理与上游之间的转发死锁。
- 规则清理：守护进程退出时清理所属 nftables 表与策略路由，也可通过 `proxy capture-cleanup` 手动清理。

### Windows 透明接管（WinDivert）

- 报文拦截：使用 WinDivert 驱动（依赖程序目录下的 `WinDivert.dll` 与 `WinDivert64.sys`），在 NETWORK 层捕获并重定向 IPv4/IPv6 报文，处理后注入系统网络栈。
- 分片重组：重组 IPv4/IPv6 分片报文，缓冲区上限 256 组、8 MiB，超时时间 15 秒。
- 系统 DNS 出口选择：查询 `type: system` 上游时，根据默认路由 metric 与接口 metric 之和选择对应出口网卡的 DNS 服务器，忽略 `fec0` 占位地址。

### DNS 解析与依赖检查

```
  [客户端 DNS 查询 (UDP/TCP 53 或 15353)]
                    │
                    ▼
            [DNS 规则匹配]
         ┌──────────┬──────────┐
         ▼          ▼          ▼
   domain/suffix  geosite    默认规则
         │          │          │
         ▼          ▼          ▼
     mainland     cn.dat     other
         │                     │
         ▼                     ▼
  [system 上游]           [DoH / SOCKS5]
  (系统物理出口DNS)       (走代理出站)
```

- 依赖循环检测：SOCKS5/HTTP 节点域名、更新下载域名及未配置 bootstrap 的 DoH 域名均由 `dns.rules` 解析。若检测到 DNS 上游与出站代理之间存在循环依赖，加载配置时报错 `DNS dependency cycle`。
- DNS 劫持：配置 `dns.hijack: true` 且 `dns.enabled: true` 时，接管 53 端口请求并转入内置 DNS 引擎处理。

### 分流与出站

- 规则按配置顺序依次匹配：`cidr`（IP 或网段）、`geoip`（国家代码库）、`port`（目标端口）、`network`（协议类型）。
- 未命中的流量由末尾未设条件的默认规则处理。
- 热重载（`proxy reload`）不中断已建立的连接，新发起的连接应用新规则。

## 快速上手

### 环境要求

- 编译工具：Go 1.26.4 或更新版本。
- Linux：内核支持 nftables、TPROXY（`CONFIG_NETFILTER_XT_TARGET_TPROXY`）与 cgroup v2；系统安装有 `iproute2`（支持 `ss --cgroup`）、`nftables`、`systemd`。
- Windows：Windows 10 2004 / Windows Server 2022 或更新版本（x64）；运行目录需放置 `WinDivert.dll` 与 `WinDivert64.sys`。

### 编译构建

从根目录编译：

```sh
# 编译所有程序 (cmd/proxy, cmd/m0, cmd/proxy-probe)
go build ./cmd/...

# 代码检查与单元测试
go vet ./...
go test ./...
```

为 Linux ARM64 交叉编译：

```powershell
$env:GOOS = "linux"
$env:GOARCH = "arm64"
go build -o ./dist/linux-arm64/proxy ./cmd/proxy
Remove-Item Env:GOOS, Env:GOARCH
```

### 运行与测试

1. 校验配置文件：
   ```sh
   go run ./cmd/proxy --config configs/m1.yaml config check
   ```

2. 前台运行：
   ```sh
   go run ./cmd/proxy --config configs/global.yaml run
   ```

3. 检查状态与连接：
   ```sh
   go run ./cmd/proxy status --json
   go run ./cmd/proxy connections list
   go run ./cmd/proxy dns test example.com --type A
   ```

## 配置说明

默认配置文件路径：
- Linux 服务模式：`/etc/proxy/proxy.yaml`
- Linux 前台模式：`~/.proxy/proxy.yaml` 或当前目录
- Windows：`%USERPROFILE%\.proxy\proxy.yaml`

### 全局配置示例（global.yaml）

```yaml
version: 1

capture:
  scope: global
  ipv4: true
  ipv6: true
  port: 15080
  udp: true

outbounds:
  direct:
    type: direct
  proxy-socks:
    type: socks5
    address: 127.0.0.1:7890
    udp: true

routing:
  rules:
    - cidr:
        - 127.0.0.0/8
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - ::1/128
        - fe80::/10
      outbound: direct
    - geoip: cn
      outbound: direct
    - outbound: proxy-socks

dns:
  enabled: true
  hijack: true
  listen:
    - '127.0.0.1:15353'
    - '[::1]:15353'
  upstreams:
    mainland:
      type: system
    remote-doh:
      type: doh
      address: https://1.1.1.1/dns-query
      outbound: proxy-socks
  rules:
    - geosite: cn
      upstream: mainland
    - domain_suffix: aliyun.com
      upstream: mainland
    - upstream: remote-doh
```

### DNS 规则语法

`dns.rules` 自上而下匹配：
- `domain`：完全匹配域名（如 `api.github.com`）。
- `domain_suffix`：匹配域名及其子域（如 `github.com` 会匹配 `raw.githubusercontent.com`）。
- `geosite`：匹配 DAT 文件分类（如 `cn`）。
- 默认规则：末尾需包含一条不带匹配条件的回退规则（如 `- upstream: remote-doh`）。

### 字段参考与默认值

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `version` | `1` | 配置版本号 |
| `capture.scope` | `off` | 接管范围：`global`、`application`、`gateway` 或 `off` |
| `capture.ipv4` / `ipv6` | `true` / `true` | 是否启用对应协议族的接管 |
| `capture.port` | `15080` | 内核重定向的目标监听端口 |
| `capture.udp` | `false` | 是否接管 UDP 流量 |
| `dns.enabled` | `false` | 是否启用内置 DNS 引擎 |
| `dns.hijack` | `false` | 是否接管 53 端口 DNS 请求 |
| `dns.timeout` | `4s` | DNS 上游请求超时时间 |
| `dns.cache.max_entries` | `4096` | DNS 响应缓存条目上限 |
| `routing.geoip_db` | `data/geoip.dat` | GeoIP 数据文件路径（相对于配置文件目录） |
| `dns.geosite_file` | `data/geosite.dat`| GeoSite 数据文件路径（相对于配置文件目录） |

## 命令行（CLI）参考

`proxy` 是管理与排错的主要入口。

### 管理命令

| 命令 | 参数与选项 | 说明 |
|---|---|---|
| `proxy run` | `--config <path>` | 在前台启动代理进程 |
| `proxy start` | `--config <path>` | 注册并启动后台服务（需要管理员权限） |
| `proxy stop` | 无 | 停止后台服务并清理网络规则 |
| `proxy restart`| 无 | 重启后台服务 |
| `proxy reload` | 无 | 重载分流规则与 DNS 策略 |
| `proxy config check` | `--config <path>` | 检查配置文件语法与依赖关系 |
| `proxy version`| 无 | 打印版本信息 |

### 状态与监控

| 命令 | 参数与选项 | 说明 |
|---|---|---|
| `proxy status` | `--json` | 查看运行时状态、连接数与丢包统计 |
| `proxy logs` | `-f, --follow` | 查看并跟踪内存日志缓冲区 |
| `proxy connections list` | `--json` | 列出当前活动连接 |

### DNS 与 Geo 数据库

| 命令 | 参数与选项 | 说明 |
|---|---|---|
| `proxy dns status` | `--json` | 查看上游请求统计与缓存状态 |
| `proxy dns flush` | 无 | 清空 DNS 内存缓存 |
| `proxy dns test <域名>` | `--type A` `--tcp` `--server <IP:PORT>` | 测试指定域名的解析流向 |
| `proxy geo status` | `--json` | 查看当前生效的 Geo 数据库版本 |
| `proxy geo update` | 无 | 检查并拉取最新 Geo 数据库 |

### 接管状态与抓包

| 命令 | 参数与选项 | 说明 |
|---|---|---|
| `proxy capture status` | `--json` | （Windows）检查 WinDivert 驱动状态 |
| `proxy capture sniff` | `--duration 10s --filter <expr>` | （Windows）限时加载驱动抓包并统计数量 |
| `proxy capture-cleanup` | 无 | （Linux）清理当前网络命名空间残留的接管规则 |

## 系统服务

### Linux（systemd）

1. 启动与注册：
   ```sh
   # 准备 /etc/proxy/proxy.yaml 后执行
   sudo proxy start
   ```
   命令会自动创建受限账号 `proxyd`，生成 systemd 单元文件，授予 `CAP_NET_ADMIN` 能力，并在 `/var/lib/proxyd` 建立运行时目录。

2. 服务管理：
   ```sh
   sudo proxy service enable     # 设置开机自启
   sudo proxy service status     # 查看服务状态
   sudo proxy logs -f            # 查看运行日志
   sudo proxy stop               # 停止服务并释放网络规则
   ```

### Windows（SCM）

1. 安装：
   - 运行安装包 `dist/installer/Proxy-Setup-x64.exe`，安装到 `C:\Program Files\Proxy`。
   - 配置文件保存在 `%USERPROFILE%\.proxy\proxy.yaml`，运行时数据在 `%USERPROFILE%\.proxy\runtime`。

2. 服务管理（以管理员身份在 PowerShell 中执行）：
   ```powershell
   proxy config check
   proxy service install
   proxy service enable
   proxy service start
   proxy status --json
   proxy service stop
   ```

## 测试与验证

### 测试脚本

- Windows：
  - `scripts/windows/m1-windows.ps1`：编译并验证回环转发与服务启停。
  - `scripts/windows/windivert-smoke-windows.ps1`：驱动加载、抓包与卸载测试。
  - `scripts/windows/windivert-relay-smoke-windows.ps1`：TCP/UDP 重定向与断网恢复测试。
  - `scripts/windows/manual-global-test-windows.ps1`：公网分流与 DNS 缓存测试。
- Linux（在隔离网络命名空间运行，不修改宿主机网络）：
  - `scripts/linux/global-linux.sh`：验证双栈全局接管与清理逻辑。
  - `scripts/linux/m3-linux.sh`：验证 53 端口 DNS 接管与系统 DNS 解析。
  - `scripts/linux/upstream-bypass-linux.sh`：验证 cgroup v2 本地 SOCKS5/Docker 上游豁免。

### 平台状态与注意事项

- Linux ARM64：已在树莓派 4 上通过原生编译、配置校验、双栈 TPROXY、cgroup 防回环与服务启停测试。
- Linux amd64：组件编译与单元测试已通过，宿主全局透明接管建议在目标发行版中确认。
- Windows x64：WinDivert 报文捕获、本地转发及应用分流已测试通过；全局接管建议通过 `scripts/windows/manual-global-test-windows.ps1` 进行实机测试。

## 开发规范

- 代码风格：使用 `gofmt` 格式化。系统特有逻辑使用 `_linux.go` 或 `_windows.go` 后缀及 `//go:build` 条件编译。
- 平台对等：新功能需在 Windows 与 Linux 两侧提供相同行为。
- 网络安全：全局接管前需确保上游进程或 cgroup 处于豁免范围，并在退出路径中包含清理逻辑。
- 提交规范：使用语义化提交前缀（如 `feat:`、`fix:`、`docs:`），提交时注明测试平台与验证命令。
