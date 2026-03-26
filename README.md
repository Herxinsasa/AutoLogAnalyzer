# AutoLogAnalyzer

AutoLogAnalyzer 是一个基于 Python 的自动日志分析 Agent 项目，集成多类日志分析技能包，支持对**业务日志**、**系统日志**和**资源统计日志**进行自动解析、异常检测与报告生成。

---

## 功能特性

| 技能包 | 分析能力 |
|---|---|
| **业务日志分析**（BusinessLogAnalyzer） | 错误率统计、慢请求检测、延迟百分位、按来源/错误聚合 |
| **系统日志分析**（SystemLogAnalyzer） | 认证失败、暴力破解 IP 检测、服务崩溃、内核错误、sudo 提权事件 |
| **资源统计日志分析**（ResourceLogAnalyzer） | CPU/内存/磁盘/负载统计（min/max/mean/P95/P99）、阈值告警、持续高负载检测 |

### 支持的日志格式（自动识别）

- **JSON Lines**（推荐，数据最丰富）
- **标准应用日志** `2024-01-01 12:00:00 [INFO] source: message`
- **Syslog / journald** `Mar 26 10:00:00 host sshd[1]: msg`
- **Apache / Nginx Combined Access Log**
- **资源指标 key=value 格式** `cpu=72.3% mem=45.1% disk=60%`
- **CSV 时间序列**

---

## 项目结构

```
AutoLogAnalyzer/
├── main.py                   # 命令行入口
├── requirements.txt
├── agent/
│   ├── __init__.py
│   └── agent.py              # AutoLogAnalyzerAgent（调度器 + 报告生成）
├── skills/
│   ├── __init__.py
│   ├── business_log.py       # 业务日志分析技能
│   ├── system_log.py         # 系统日志分析技能
│   └── resource_log.py       # 资源统计日志分析技能
├── utils/
│   ├── __init__.py
│   └── log_parser.py         # 多格式日志解析器
└── tests/
    ├── test_agent.py
    ├── test_business_log.py
    ├── test_system_log.py
    └── test_resource_log.py
```

---

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 命令行使用

```bash
# 自动识别日志类型并生成报告
python main.py app.log --type auto

# 分析业务日志（设置慢请求阈值为 500ms）
python main.py app.log --type business --slow-threshold-ms 500

# 分析系统日志（设置暴力破解检测阈值为 3 次）
python main.py /var/log/auth.log --type system --brute-force-threshold 3

# 分析资源统计日志，输出 JSON
python main.py metrics.log --type resource --json
```

**命令行参数：**

```
usage: autologanalyzer [-h] [--type {business,system,resource,auto}]
                       [--json] [--slow-threshold-ms MS]
                       [--brute-force-threshold N] [--top-n N]
                       log_file
```

### Python API 使用

```python
from agent.agent import AutoLogAnalyzerAgent, LogType

agent = AutoLogAnalyzerAgent(
    slow_threshold_ms=1000.0,      # 慢请求阈值（ms）
    brute_force_threshold=5,       # 暴力破解 IP 检测阈值（失败次数）
    top_n=10,                      # 汇总报告中展示的 Top-N 条数
)

# 分析文件（自动识别类型）
result = agent.analyze_file("app.log", log_type=LogType.AUTO)

# 打印可读报告
agent.print_report(result)

# 输出 JSON
print(agent.to_json(result))
```

也可以直接使用各技能包：

```python
from skills.business_log import BusinessLogAnalyzer
from skills.system_log import SystemLogAnalyzer
from skills.resource_log import ResourceLogAnalyzer

# 业务日志
analyzer = BusinessLogAnalyzer(slow_threshold_ms=500)
result = analyzer.analyze_file("app.log")

# 系统日志
analyzer = SystemLogAnalyzer(brute_force_threshold=3)
result = analyzer.analyze_file("/var/log/syslog")

# 资源日志
analyzer = ResourceLogAnalyzer(thresholds={"cpu_pct": 80.0, "mem_pct": 85.0})
result = analyzer.analyze_file("metrics.log")
```

---

## 报告示例

### 业务日志

```
====================================================================
  AutoLogAnalyzer Report
====================================================================
  Source   : app.log
  Log Type : business
  Analyzed : 2024-01-01T12:00:00
====================================================================
  Total log entries : 9
  Error rate        : 33.33%

  Log Level Distribution:
    INFO                                      5
    ERROR                                     2
    WARNING                                   1
    CRITICAL                                  1

  Latency Statistics (ms):
    count       : 5
    min_ms      : 120.0
    max_ms      : 2500.0
    mean_ms     : 984.0
    p95_ms      : 2240.0
    p99_ms      : 2448.0

  Slow Requests (sample):
--------------------------------------------------------------------
  time=...  latency_ms=2500.0  message=Payment gateway timeout
```

### 系统日志

```
  Total log entries       : 8
  Auth failures           : 5
  Brute-force IPs detected:
     192.168.1.100         5 failures
```

### 资源统计日志

```
  Per-Metric Statistics:
  Metric                Count      Min     Mean      Max      P95      P99
  cpu_pct                   8    20.00    78.54    95.00    93.95    94.79
  mem_pct                   8    30.00    72.51    93.00    92.65    92.93

  Sustained High-Utilization Events:
    cpu_pct: 91.2 (peak 95.0) for 5 consecutive samples
```

---

## 运行测试

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## 许可证

MIT
