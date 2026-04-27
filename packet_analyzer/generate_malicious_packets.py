# -*- coding: utf-8 -*-
"""生成恶意测试包"""
import socket
import time

def send_malicious_http(target_host="127.0.0.1", target_port=8080):
    """发送包含恶意 payload 的 HTTP 请求"""

    test_cases = [
        # SQL 注入
        ("SQL注入", "GET /api/user?id=1' OR '1'='1 HTTP/1.1\r\nHost: test.com\r\n\r\n"),

        # XSS 攻击
        ("XSS攻击", "GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: test.com\r\n\r\n"),

        # 命令注入
        ("命令注入", "POST /exec HTTP/1.1\r\nHost: test.com\r\nContent-Length: 30\r\n\r\ncmd=powershell.exe -c whoami"),

        # 路径遍历
        ("路径遍历", "GET /file?path=../../../etc/passwd HTTP/1.1\r\nHost: test.com\r\n\r\n"),

        # 另一个 SQL 注入
        ("SQL注入2", "GET /login?user=admin&pass=x' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: test.com\r\n\r\n"),
    ]

    print(f"开始发送恶意测试包到 {target_host}:{target_port}")
    print("=" * 60)

    for name, payload in test_cases:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            print(f"\n[{name}] 发送中...")
            sock.connect((target_host, target_port))
            sock.send(payload.encode())

            # 尝试接收响应（可能会超时，没关系）
            try:
                response = sock.recv(1024)
                print(f"  响应: {response[:50]}...")
            except socket.timeout:
                print(f"  已发送（无响应）")

            sock.close()
            time.sleep(1)  # 间隔 1 秒

        except Exception as e:
            print(f"  发送失败: {e}")

    print("\n" + "=" * 60)
    print("测试完成！检查抓包工具是否检测到威胁。")

if __name__ == "__main__":
    print("恶意包生成器")
    print("注意：这些包只用于测试，不会造成实际危害\n")

    # 选项 1: 发送到本地测试服务器
    print("选项 1: 发送到本地服务器（需要先启动一个测试服务器）")
    print("选项 2: 发送到公网服务器（会被抓包工具捕获）")

    choice = input("\n选择 (1/2，直接回车默认为 1): ").strip() or "1"

    if choice == "1":
        # 本地测试
        print("\n请先在另一个终端启动测试服务器:")
        print("  python -m http.server 8080")
        input("启动后按回车继续...")
        send_malicious_http("127.0.0.1", 8080)
    else:
        # 发送到公网（会被抓包）
        print("\n将发送到 httpbin.org（公共测试服务）")
        send_malicious_http("httpbin.org", 80)
