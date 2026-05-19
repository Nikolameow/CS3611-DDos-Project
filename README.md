# CS3611 DDoS Project

SJTU CS3611 计算机网络课程项目：DDoS 攻击模拟、基础防御与基于流量特征的智能检测。所有攻击流量仅允许在本机回环地址、RFC1918 私有地址或 Mininet 虚拟网络中运行，禁止对公网目标测试。

## 项目结构

- `topology/topo.py`：主驱动文件，创建 Mininet 拓扑并串联攻防演示。
- `attack1/`：攻击与流量生成模块，提供 HTTP Flood、TCP connection flood、UDP 反射风格模拟、PCAP 生成与基础特征统计。
- `defense/`：防御入口，封装 iptables 限速、IP 黑名单、nftables HTTP 端口过滤和日志自动封禁。
- `detection/`：离线检测模块，从 PCAP 提取窗口特征，运行 MLP 多分类模型和 K-Means 异常检测模型。

## 环境准备

Python 依赖：

```bash
# 如果系统没有 pip，先安装：sudo apt install python3-pip
python3 -m pip install -r requirements.txt
```

系统依赖需要由实验环境提供：

- Mininet 与 Open vSwitch：运行 `topology/topo.py`。
- `iptables`：TCP 端口限速与黑名单。
- `nft`：nftables HTTP 端口过滤，可选。
- `tcpdump`：自动演示抓包与实时统计封禁，可选但推荐。

## 一键攻防演示

在项目根目录运行：

```bash
sudo python3 topology/topo.py --demo
```

默认流程如下：

1. `topology/topo.py` 创建 `h1`、`h2`、`h3` 三个攻击节点，`h4` 正常用户节点，`victim` 受害/防御节点。
2. `victim` 启动 `attack1` 中的 HTTP demo server，监听 `10.0.0.100:8080`。
3. `victim` 通过 `defense/defense_main.py` 应用 iptables 端口限速规则。
4. 如果传入 `--nft`，脚本会额外尝试应用 nftables HTTP 过滤规则；系统缺少 `nft` 时会提示但不中断主流程。
5. `victim` 使用 `tcpdump` 抓取 `victim-eth0` 上的 HTTP 流量，输出到 `detection/data/demo_http_flood.pcap`。
6. `victim` 启动 `live-block` 实时统计源 IP 请求频率，超过阈值后调用 iptables 黑名单。
7. `h1` 发起 HTTP Flood，`h2` 优先发起 raw SYN spoof flood（无 raw socket 权限时回退 TCP connection flood），`h3` 发起 POST Flood，`h4` 发送正常 HTTP 流量。
8. 抓包结束后，主进程调用 `detection.features` 生成 `detection/data/demo_features.csv`。
9. 主进程调用 `detection.predict_classifier` 和 `detection.predict_anomaly`，输出分类和异常检测结果。

可调整演示时长和攻击速率：

```bash
sudo python3 topology/topo.py --demo --duration 12 --rate 180
sudo python3 topology/topo.py --demo --nft
```

如果只想进入 Mininet CLI 手动实验：

```bash
sudo python3 topology/topo.py --cli
```

## 攻击模块

攻击模块从 `attack1/` 目录以 Python module 方式运行：

```bash
cd attack1
python3 -m attack_sim demo-server --host 0.0.0.0 --port 8080
python3 -m attack_sim http --url http://10.0.0.100:8080/ --duration 10 --rate 100 --randomize
python3 -m attack_sim syn --host 10.0.0.100 --port 8080 --duration 10 --rate 200
sudo python3 -m attack_sim raw-syn --target 10.0.0.100 --port 8080 --duration 10 --rate 800
python3 -m attack_sim normal-http --url http://10.0.0.100:8080/ --duration 10 --rate 20
```

安全边界由 `attack1/attack_sim/guards.py` 强制执行：目标必须解析为回环地址或私有实验网段地址，例如 `127.0.0.1`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`。公网 IP 会被拒绝。

注意：`raw-syn` 命令会发送伪造私有源 IP 的 raw SYN 包，需要 root/CAP_NET_RAW，仅允许在回环、私网或 Mininet 目标中使用。`syn` 命令保留为不需要 raw socket 的高并发 TCP 连接洪泛回退方案。伪造源 IP 的 SYN/UDP 反射样本也可由 PCAP 合成命令生成，用于离线分析和模型训练。

## 防御模块

统一入口：

```bash
python3 defense/defense_main.py rules --mode demo
python3 defense/defense_main.py rules --mode rate-limit --port 8080 --rate 50 --burst 50 --apply
python3 defense/defense_main.py rules --mode blacklist --ip 10.0.0.3 --apply
python3 defense/defense_main.py rules --mode nft-http --port 8080 --rate 50 --apply
sudo python3 defense/defense_main.py live-block --interface victim-eth0 --port 8080 --threshold 1000 --window 60 --apply
```

默认不加 `--apply` 时只打印规则，便于检查。加 `--apply` 后会真正执行系统命令。端口限速使用 iptables `hashlimit` 按源 IP 计数，符合“单个 IP 连接速率”限制语义。

自动封禁日志示例：

```bash
python3 defense/defense_main.py auto-block --log-file /var/log/kern.log --threshold 1000 --window 60 --apply
```

自动封禁会持续读取日志新增行，提取 `SRC=<ip>` 或 `src=<ip>`，当同一 IP 在窗口内超过阈值时加入 iptables 黑名单。

实时接口封禁示例：

```bash
sudo python3 defense/defense_main.py live-block --interface victim-eth0 --port 8080 --threshold 1000 --window 60 --apply
```

该命令通过 `tcpdump` 监控接口流量，按源 IP 在滑动窗口内统计访问目标端口的次数，超过阈值后调用 iptables 黑名单。

## 检测模块

离线检测流程：

```bash
python3 -m detection.features
python3 -m detection.train_mlp
python3 -m detection.train_kmeans
python3 -m detection.predict_classifier
python3 -m detection.predict_anomaly
```

`detection.features` 默认读取 `attack1/data/*.pcap`，按 0.05 秒窗口提取 PPS、包大小、协议比例、HTTP 比例、SYN/ACK 比例、源/目的 IP 熵、源/目的端口熵、流数量、包间隔波动和小包/大包比例等特征。训练好的模型保存在 `detection/models/`。

一键演示产生的检测文件：

- `detection/data/demo_http_flood.pcap`
- `detection/data/demo_features.csv`
- `detection/data/demo_classifier_predictions.csv`
- `detection/data/demo_anomaly_predictions.csv`

## 攻防闭环

当前闭环分为两层：

1. 基础防御闭环：`topology/topo.py` 在 victim 上应用 iptables/nftables 规则，攻击流量经过 victim namespace 时被限速或过滤。
2. 智能检测闭环：演示结束后对本次 PCAP 做特征提取和模型推理，输出攻击类型与异常状态，用于报告和后续自动化响应扩展。

模型预测结果目前不会自动修改防火墙规则；实际阻断由 iptables/nftables、日志自动封禁和实时接口统计封禁负责。
