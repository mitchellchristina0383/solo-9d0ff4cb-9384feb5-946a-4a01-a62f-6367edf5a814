# PCAP HTTP/1.1 Flow Analyzer + 网关双点转发核对

面向网络值班的抓包分析 API，提供两类能力：

1. **单抓包 HTTP/1.1 分析**：上传以太网 / IPv4 / TCP 抓包（pcap 或 pcapng），
   对**完整捕获三次握手、目的端口 80、且每连接仅有一次 HTTP/1.1 请求**的连接，
   返回**请求行、Host、响应状态码和连接标识**。
2. **双点转发核对（新增）**：上传在网关**入口、出口两侧**分别抓取、覆盖同一时段、
   网络无 NAT 的两份以太网 PCAP，按完整握手区分四元组复用的连接，再按方向、
   TCP 序列号和内容逐字节核对有效载荷，报告**入口可见、出口未见的字节范围及入口
   报文号**，用于排查疑似转发缺口；存在歧义时一律列为**待核（review），不得定性为
   丢包**。

## 快速开始

```bash
docker compose up --build
# 打开 http://localhost:8000/docs
# 单抓包：POST /analyze 上传 pcap 文件；仓库自带样例 samples/sample.pcap，
#         也可先 GET /sample 下载样例再上传，或直接 POST /analyze/sample。
# 双点核对：POST /crosscheck 同时上传入口、出口两份抓包
#         （表单字段 ingress、egress）；可先 GET /samples/crosscheck/ingress
#         与 /samples/crosscheck/egress 下载内置样例，或直接
#         POST /crosscheck/sample 分析内置样例对。
```

本地运行（无 Docker）：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## API

| 端点 | 说明 |
| --- | --- |
| `POST /analyze` | 上传单份 pcap/pcapng（表单字段 `file`），返回 HTTP 分析结果 JSON |
| `GET /sample` | 下载内置单抓包样例 `sample.pcap` |
| `POST /analyze/sample` | 直接分析内置单抓包样例 |
| `POST /crosscheck` | 上传入口、出口两份抓包（表单字段 `ingress`、`egress`），返回转发核对 JSON |
| `GET /samples/crosscheck/ingress` | 下载双点核对的入口样例 |
| `GET /samples/crosscheck/egress` | 下载双点核对的出口样例 |
| `POST /crosscheck/sample` | 直接对内置样例对执行双点核对 |
| `GET /docs` | Swagger UI（可在线上传文件） |

## 双点转发核对

### 前提与配对

- 两份抓包覆盖**同一时段**、同一批以太网/IPv4/TCP 流量，且**无 NAT**：
  因此两侧四元组、TCP 序列号完全一致。
- 连接以**完整三次握手**为锚点拆分：四元组在 TIME_WAIT 后被复用时，按各自 ISN
  区分成独立连接实例，不会把旧连接的数据算到新连接上。
- 配对键为 `(四元组, 客户端 ISN, 服务端 ISN)`。仅当两侧各有且仅有一个同签名实例时
  才逐字节比对；否则整条记为**待核**。

### 字节核对规则（按方向各自进行）

- 以相对 ISN 的序列号归并载荷；两侧**分段方式、到达顺序不同**视为等价。
- 完全相同的重传、镜像口重复报文**只计一次**，不重复计数。
- 同序列号重叠但**内容不一致**记为冲突，连接判**待核**，且这些字节不计为缺口。
- 入口自身存在的内部空洞（入口都没抓到）不算转发缺口。
- 入口覆盖、出口缺失（或出口长度不足）的连续字节合并成缺口区间，给出相对偏移、
  起止绝对序列号、以及携带这些字节的**入口报文号（1 起，与 Wireshark/tcpdump
  帧号一致）**。

### 三种结论

| status | 含义 |
| --- | --- |
| `verified` | 双向有效载荷逐字节一致，无任何待核事项 |
| `gap_found` | 存在入口有、出口无的字节区间，且无任何待核事项（疑似转发缺口） |
| `review`（待核） | 证据不足，**不得定性为丢包**；原始缺口区间仍会展示供人工排查 |

以下情况一律 `review`：

- 连接配对不唯一（同签名出现多个实例）；
- 同一序列号两侧内容冲突；
- 相关报文被 snaplen **截断**（入口或出口）；
- 入口连接落在出口采集时间窗之外，或两侧采集时段整体不重合；
- 某条完整连接只在一侧出现（无对端），或某侧只有无完整握手、无法锚定的报文。

### 结果结构（节选）

```jsonc
{
  "summary": {
    "ingress_packets": 73, "egress_packets": 59,
    "ingress_connections": 8, "egress_connections": 7,
    "paired_connections": 7,
    "verified": 2, "gap_found": 2, "review": 4,
    "missing_bytes_total": 41          // 仅统计 gap_found，待核不计入
  },
  "capture_windows": { "ingress": {...}, "egress": {...}, "overlap": true },
  "review_reasons": [],                // 全局待核原因（如时间窗完全不重合）
  "connections": [
    {
      "id": 1, "status": "gap_found", "review_reasons": [],
      "connection": { "client": "10.1.0.2:51002", "server": "203.0.113.10:80",
                      "client_isn": 1000, "server_isn": 5000, ... },
      "ingress": { "packets": 8, "handshake_complete": true, ... },
      "egress":  { "packets": 7, "handshake_complete": true, ... },
      "directions": {
        "client_to_server": {
          "ingress_covered_bytes": 52, "egress_covered_bytes": 32,
          "matched_bytes": 32, "missing_bytes": 20,
          "missing_ranges": [
            { "offset": 20, "length": 20,
              "seq_start": 1021, "seq_end": 1040,
              "ingress_packet_numbers": [17] }
          ],
          "cross_conflict_ranges": [], "ingress_internal_gaps": [],
          "truncated_ingress": false, "truncated_egress": false
        },
        "server_to_client": { ... }
      },
      "missing_total_bytes": 20
    }
  ]
}
```

### 双点样例覆盖的场景

`samples/crosscheck-ingress.pcap` / `crosscheck-egress.pcap`
（由 `scripts/make_crosscheck_pcaps.py` 生成，可重新生成）：

| 客户端端口 | 场景 | 预期结论 |
| --- | --- | --- |
| 51001 | 两侧分段/到达顺序不同，含重传与镜像重复 | verified |
| 51002 | 入口一个数据段出口缺失 | gap_found（报入口报文号） |
| 51003 | 同一四元组两次完整握手（ISN 不同），第二实例出口缺段 | 一 verified、一 gap_found |
| 51004 | 同序列号出口内容不同 | review（内容冲突，不算丢包） |
| 51005 | 出口报文被 snaplen 截断 | review（截断） |
| 51006 | 整条连接只在入口出现 | review（无出口对端） |
| 51007 | 出口缺段但该连接两侧采集时间窗不重合 | review（时段不重合） |

### 结果结构

```jsonc
{
  "summary": { "tcp_segments": 75, "flows": 9, "ok": 2, "unreliable": 3, "skipped": 4 },
  "flows": [
    {
      "id": 0,
      "status": "ok",                    // ok | unreliable | skipped
      "connection": { "client": "10.0.0.10:50001", "server": "93.184.216.34:80", ... },
      "request":  { "request_line": "GET /index.html HTTP/1.1", "method": "GET",
                    "target": "/index.html", "version": "HTTP/1.1", "host": "example.com" },
      "response": { "status_line": "HTTP/1.1 200 OK", "status_code": 200, ... },
      "directions": {
        "client_to_server": { "reliable": true, "header_complete": true,
                              "reassembled_bytes": 60, "gaps": [], "conflicts": [],
                              "truncated": false, ... },
        "server_to_client": { ... }
      },
      "reasons": []
    }
  ]
}
```

## 判定规则

- **流筛选**：必须完整捕获 SYN / SYN-ACK / ACK 三次握手；服务器端口必须为 80；
  请求必须是 HTTP/1.1；一条连接上只允许一个请求（检测到流水线/第二个请求即跳过，
  避免把响应误配给别的请求）。
- **字节还原**：每个方向按 TCP 序列号（相对于各自 ISN）归并；乱序报文按序号排序，
  同内容重传/重叠只计一次。
- **可靠性**（按方向判定，只关心头部结束之前的字节）：
  - 头部结束（`\r\n\r\n`）之前存在**缺口** → 该方向 unreliable；
  - 重叠字节**内容冲突** → 该方向 unreliable；
  - 任一报文被 snaplen **截断**（捕获长度 < 线上长度且载荷受损）→ 该方向 unreliable；
  - 头部始终未完整出现 → 该方向 unreliable。
- 一个方向不可靠时，**另一个方向的结果照常返回**（例如请求缺缺口但响应完整，
  仍返回响应状态码，请求字段为 null）；响应永远只与同一连接配对，绝不跨连接猜测。
- 头部结束之后的缺口/冲突不影响判定（本工具只取请求行、Host、状态码）。

## 样例 PCAP 覆盖的场景

`samples/sample.pcap`（由 `scripts/make_sample_pcap.py` 生成，可重新生成）：

| 客户端端口 | 场景 | 预期状态 |
| --- | --- | --- |
| 50001 | 普通 OK，请求/响应头各跨 2 个报文 | ok |
| 50002 | 乱序 + 同内容重传 | ok（不重复计数） |
| 50003 | 请求头中间缺一段 | unreliable（响应 404 仍返回） |
| 50004 | 响应重叠字节冲突（200 vs 500） | unreliable（请求仍返回） |
| 50005 | 无三次握手 | skipped |
| 50006 | 目的端口 8080 | skipped |
| 50007 | 流水线两个请求 | skipped |
| 50008 | 请求报文被截断 | unreliable（响应 200 仍返回） |
| 50009 | HTTP/1.0 请求 | skipped |

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

覆盖：重传去重、乱序归并、缺口检测、重叠冲突、截断标记、握手完整性、
端口过滤、单请求限制，以及基于样例 PCAP 的 API 端到端断言。

双点核对额外覆盖（`tests/test_crosscheck.py`、`tests/test_crosscheck_api.py`）：
四元组复用拆分、重传 SYN 合流、跨段缺口归并与入口报文号、重传/镜像不重复计数、
同序列内容冲突、入口/出口截断、单侧缺失连接、配对不唯一、采集时间窗不重合，
以及内置双点样例的端到端分类断言。

## 已知限制

- 不重组 IP 分片（分片报文被跳过，在流上表现为缺口 → 该方向 unreliable / 待核）。
- 不解析 TLS；`Transfer-Encoding: chunked` 的请求体长度不用于“第二请求”检测
  （请求带 chunked body 且同连接还有后续请求时可能漏判多请求）。
- 单抓包 HTTP 分析中，同一四元组在捕获内被重复用于多条连接（TIME_WAIT 后重建）时
  按一条流处理；**双点核对**则会按握手拆成独立实例，不受此限制影响。
- pcapng 时间戳按默认微秒分辨率解析（不读取 `if_tsresol` 选项）。
- 双点核对假设**无 NAT、无时间戳改写**，依赖两侧序列号一致；若存在 NAT 或序列号
  重写，四元组/ISN 配对会失败并落入待核，而不会猜测对应关系。
- 双点核对的序列空间覆盖按字节保存在内存中（含每字节来源报文列表），面向值班排查
  的常规抓包规模；超大流量长连接的内存占用随连接内字节数线性增长。
- 同时打开（simultaneous open，两端都发 SYN）等非常规握手不在拆分器专门处理范围内，
  此类连接通常会因握手不完整而列为待核。
