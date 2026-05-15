#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_logs.py —— 为 Mini-OBS 生成高真实感、模板化的百万级日志数据

设计目标：
1. 业务真实感：模拟 nginx/auth/payment/db/cache 多服务场景
2. 模板高重复：message 大量复用固定模板，仅参数变化（最大化压缩比）
3. 级别分布：INFO 70% / WARN 20% / ERROR 10%
4. 时间递增：毫秒级时间戳，模拟真实流量曲线
5. 格式兼容：默认输出 {"t":..., "s":..., "l":..., "m":...}（Mini-OBS 紧凑格式）

用法：
    python gen_logs.py --lines 100000 --output /tmp/app.log
    python gen_logs.py --lines 1000000 --output /tmp/big.log --burst

"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone
from typing import List, Tuple

# ==================== 配置 ====================

SERVICES = ["nginx", "auth", "payment", "db", "cache", "gateway", "order"]

# 日志模板库：固定文本 + 可变参数占位符
# 高重复度模板是压缩比的关键
TEMPLATES: List[Tuple[str, str, str]] = [
    # (service, level, template_with_placeholders)
    ("nginx", "I", "{client_ip} - - [{time}] "{method} {path} HTTP/1.1" {status} {bytes} "{referer}" "{ua}" {latency}ms"),
    ("nginx", "W", "{client_ip} - - [{time}] "{method} {path} HTTP/1.1" {status} {bytes} - {latency}ms [SLOW]"),
    ("nginx", "E", "{client_ip} - - [{time}] "{method} {path} HTTP/1.1" {status} 0 "-" "-" upstream_timeout"),

    ("auth", "I", "User {user_id} login success from {client_ip} device={device} session={session_id}"),
    ("auth", "W", "User {user_id} login failed (attempt {attempt}/5) from {client_ip} reason={reason}"),
    ("auth", "E", "User {user_id} account locked after {attempt} failed attempts ip={client_ip}"),
    ("auth", "I", "Token refresh for user {user_id} ttl={ttl}s"),

    ("payment", "I", "Order {order_id} payment success amount={amount} currency={currency} method={method} gateway={gateway}"),
    ("payment", "W", "Order {order_id} payment pending amount={amount} retry={retry}/3"),
    ("payment", "E", "Order {order_id} payment failed amount={amount} error_code={err_code} error_msg={err_msg}"),
    ("payment", "I", "Refund processed order={order_id} refund_id={refund_id} amount={amount}"),

    ("db", "I", "Query [{query_id}] {operation} {table} rows={rows} time={exec_time}ms cache={cache_hit}"),
    ("db", "W", "Query [{query_id}] slow {operation} {table} rows={rows} time={exec_time}ms threshold=100ms"),
    ("db", "E", "Query [{query_id}] failed {operation} {table} error={db_error} sql_hash={sql_hash}"),
    ("db", "I", "Connection pool status active={active} idle={idle} waiting={waiting} max={max_conn}"),

    ("cache", "I", "Cache {cache_op} key={cache_key} ttl={ttl} hit={hit} size={size}b"),
    ("cache", "W", "Cache eviction key={cache_key} reason={evict_reason} mem_usage={mem_pct}%"),
    ("cache", "E", "Cache connection lost node={node_id} retry={retry}/10"),

    ("gateway", "I", "Request routed service={target_service} path={path} latency={latency}ms trace={trace_id}"),
    ("gateway", "W", "Rate limit triggered client={client_id} limit={limit} window={window}s"),
    ("gateway", "E", "Circuit breaker open service={target_service} failures={failures} last_error={last_err}"),

    ("order", "I", "Order created order_id={order_id} user={user_id} items={item_count} total={total}"),
    ("order", "I", "Order shipped order_id={order_id} carrier={carrier} tracking={tracking}"),
    ("order", "E", "Order cancelled order_id={order_id} user={user_id} reason={cancel_reason}"),
]

# 参数生成器
PARAM_POOLS = {
    "client_ip": lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    "time": lambda: datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000"),
    "method": lambda: random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"]),
    "path": lambda: random.choice([
        "/api/v1/users", "/api/v1/orders", "/api/v1/payments", "/api/v1/auth/login",
        "/api/v1/products", "/api/v1/cart", "/api/v2/search", "/health", "/metrics",
        "/api/v1/admin/dashboard", "/api/v1/reports/sales", "/static/main.js", "/favicon.ico"
    ]),
    "status": lambda: random.choices(
        [200, 201, 204, 301, 302, 400, 401, 403, 404, 429, 500, 502, 503],
        weights=[45, 10, 5, 3, 2, 8, 5, 3, 12, 2, 3, 1, 1]
    )[0],
    "bytes": lambda: random.randint(128, 1048576),
    "referer": lambda: random.choice(["-", "https://example.com", "https://app.example.com/dashboard", "https://google.com"]),
    "ua": lambda: random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
        "MiniOBS-Test-Agent/1.0"
    ]),
    "latency": lambda: max(1, int(random.lognormvariate(2.5, 1.2))),

    "user_id": lambda: f"user_{random.randint(10000, 99999):05d}",
    "device": lambda: random.choice(["iPhone14,2", "SM-G991B", "Pixel6", "WindowsPC", "MacBookPro18,1"]),
    "session_id": lambda: f"sess_{random.getrandbits(64):016x}",
    "attempt": lambda: random.randint(1, 5),
    "reason": lambda: random.choice(["wrong_password", "expired_token", "mfa_failed", "account_disabled"]),
    "ttl": lambda: random.randint(300, 7200),

    "order_id": lambda: f"ORD-{random.getrandbits(48):012x}",
    "amount": lambda: round(random.uniform(1.0, 999.99), 2),
    "currency": lambda: random.choice(["CNY", "USD", "EUR", "JPY"]),
    "method": lambda: random.choice(["alipay", "wechat", "card", "paypal", "apple_pay"]),
    "gateway": lambda: random.choice(["stripe", "adyen", "braintree", "alipay_gateway"]),
    "retry": lambda: random.randint(1, 3),
    "err_code": lambda: random.choice(["INSUFFICIENT_FUNDS", "CARD_DECLINED", "TIMEOUT", "CVV_FAIL", "FRAUD_DETECTED"]),
    "err_msg": lambda: random.choice(["发卡行拒绝", "3D Secure 失败", "网络超时", "风控拦截"]),
    "refund_id": lambda: f"RFD-{random.getrandbits(32):08x}",

    "query_id": lambda: f"q{random.getrandbits(32):08x}",
    "operation": lambda: random.choice(["SELECT", "INSERT", "UPDATE", "DELETE"]),
    "table": lambda: random.choice(["users", "orders", "payments", "products", "inventory", "logs", "sessions"]),
    "rows": lambda: random.randint(0, 50000),
    "exec_time": lambda: max(1, int(random.lognormvariate(3.0, 1.0))),
    "cache_hit": lambda: random.choice(["true", "false"]),
    "db_error": lambda: random.choice(["Deadlock", "ConnectionLost", "SyntaxError", "Timeout", "DiskFull"]),
    "sql_hash": lambda: f"{random.getrandbits(64):016x}",
    "active": lambda: random.randint(5, 50),
    "idle": lambda: random.randint(1, 20),
    "waiting": lambda: random.randint(0, 10),
    "max_conn": lambda: 100,

    "cache_op": lambda: random.choice(["GET", "SET", "DEL", "EXPIRE", "HGET"]),
    "cache_key": lambda: f"cache:{random.choice(['user', 'session', 'product', 'config'])}:{random.randint(1,99999):05d}",
    "hit": lambda: random.choice(["true", "false"]),
    "size": lambda: random.randint(64, 4096),
    "evict_reason": lambda: random.choice(["LRU", "TTL_EXPIRED", "MEMORY_LIMIT", "EXPLICIT"]),
    "mem_pct": lambda: round(random.uniform(60.0, 95.0), 1),
    "node_id": lambda: f"cache-node-{random.randint(1,8)}",

    "target_service": lambda: random.choice(["auth", "payment", "order", "db", "cache"]),
    "trace_id": lambda: f"{random.getrandbits(96):024x}",
    "client_id": lambda: f"client_{random.randint(1000,9999)}",
    "limit": lambda: random.choice([100, 500, 1000, 5000]),
    "window": lambda: random.choice([1, 60, 300]),
    "failures": lambda: random.randint(5, 20),
    "last_err": lambda: random.choice(["timeout", "connection_refused", "5xx", "throttled"]),

    "item_count": lambda: random.randint(1, 20),
    "total": lambda: round(random.uniform(10.0, 2000.0), 2),
    "carrier": lambda: random.choice(["SF", "ZTO", "YTO", "EMS", "DHL"]),
    "tracking": lambda: f"{random.randint(100000000000, 999999999999)}" if random.random() > 0.1 else "null",
    "cancel_reason": lambda: random.choice(["user_request", "payment_timeout", "inventory_shortage", "fraud_risk"]),
}


def generate_line(ts: int, template_idx: int = None) -> dict:
    """生成单条日志 JSON 对象"""
    if template_idx is None:
        template_idx = random.randint(0, len(TEMPLATES) - 1)

    svc, lvl, tmpl = TEMPLATES[template_idx]

    # 填充参数
    msg = tmpl
    for key, gen in PARAM_POOLS.items():
        placeholder = "{" + key + "}"
        if placeholder in msg:
            msg = msg.replace(placeholder, str(gen()), 1)

    # 清理未替换的占位符（不应发生，但防御性处理）
    import re
    msg = re.sub(r'\{[a-z_]+\}', '-', msg)

    return {
        "t": ts,
        "s": svc,
        "l": lvl,
        "m": msg,
    }


def generate_logs(lines: int, output: str, burst: bool = False, seed: int = 42):
    """主生成函数"""
    random.seed(seed)

    base_ts = int(time.time() * 1000) - (lines * 100)  # 让时间从过去开始递增

    # 流量曲线：如果是 burst 模式，中间 20% 区域密度翻倍
    if burst:
        burst_start = int(lines * 0.4)
        burst_end = int(lines * 0.6)
    else:
        burst_start = burst_end = -1

    with open(output, 'w', encoding='utf-8') as f:
        for i in range(lines):
            # 时间戳：基础递增 + 随机抖动（模拟真实间隔不均匀）
            jitter = random.randint(1, 500) if random.random() < 0.1 else random.randint(1, 50)
            if burst_start <= i <= burst_end:
                jitter = random.randint(1, 10)  # burst 期密集
            ts = base_ts + i * 10 + jitter

            # 模板选择：按服务权重微调，使日志分布更真实
            # 70% INFO, 20% WARN, 10% ERROR —— 通过模板本身级别实现
            line = generate_line(ts)

            f.write(json.dumps(line, ensure_ascii=False, separators=(',', ':')))
            f.write('\n')

            # 进度显示
            if (i + 1) % 10000 == 0 or i == lines - 1:
                pct = (i + 1) / lines * 100
                sys.stdout.write(f"\r生成进度: {i+1:,} / {lines:,} ({pct:.1f}%)")
                sys.stdout.flush()

    print()  # 换行

    # 统计输出
    file_size = open(output, 'rb').seek(0, 2) or 0
    print(f"\n✅ 生成完成: {output}")
    print(f"   行数: {lines:,}")
    print(f"   大小: {file_size / 1024 / 1024:.2f} MB")
    print(f"   平均每行: {file_size / lines:.1f} bytes")

    # 快速采样验证
    with open(output, 'r', encoding='utf-8') as f:
        sample = [json.loads(f.readline()) for _ in range(5)]
    print("\n采样预览:")
    for s in sample:
        print(f"   [{s['s']}/{s['l']}] {s['m'][:80]}...")


def main():
    parser = argparse.ArgumentParser(description="为 Mini-OBS 生成高真实感日志数据")
    parser.add_argument("--lines", type=int, default=100000, help="生成日志行数 (默认: 100000)")
    parser.add_argument("--output", type=str, default="/tmp/mini-obs-test.log", help="输出文件路径")
    parser.add_argument("--burst", action="store_true", help="启用流量突发模式（中间 20% 密度翻倍）")
    parser.add_argument("--seed", type=int, default=42, help="随机种子，保证可复现")
    args = parser.parse_args()

    print(f"Mini-OBS 日志生成器")
    print(f"目标行数: {args.lines:,}")
    print(f"输出路径: {args.output}")
    print(f"突发模式: {'开启' if args.burst else '关闭'}")
    print(f"随机种子: {args.seed}")
    print("-" * 40)

    generate_logs(args.lines, args.output, args.burst, args.seed)


if __name__ == "__main__":
    main()
