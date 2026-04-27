# -*- coding: utf-8 -*-
"""快速诊断脚本"""
import subprocess
import sys
import time
import json

print("=== 诊断开始 ===\n")

# 1. 测试抓包（不用 LLM）
print("1. 测试抓包功能（10秒内抓5个包，不调用LLM）...")
try:
    result = subprocess.run(
        ["python", "improved_packet_analyzer.py", "capture",
         "-i", "1", "-c", "5", "--provider", "off"],
        timeout=15,
        capture_output=True,
        text=True
    )

    lines = result.stdout.strip().split('\n')
    packet_count = sum(1 for line in lines if '"id":' in line)

    if packet_count > 0:
        print(f"   [OK] 抓包正常，捕获了 {packet_count} 个包")
    else:
        print(f"   [FAIL] 抓包失败或无流量")
        print(f"   输出: {result.stdout[:200]}")

except subprocess.TimeoutExpired:
    print("   [FAIL] 抓包超时（可能网卡无流量）")
except Exception as e:
    print(f"   [FAIL] 错误: {e}")

# 2. 测试 LLM 连接
print("\n2. 测试 LLM 连接...")
try:
    result = subprocess.run(
        ["python", "improved_packet_analyzer.py", "test-connection",
         "--provider", "ollama", "--model", "deepseek-r1:8b"],
        timeout=15,
        capture_output=True,
        text=True
    )

    try:
        response = json.loads(result.stdout.strip())
        if response.get("success"):
            print(f"   [OK] LLM 连接正常: {response.get('message')}")
        else:
            print(f"   [FAIL] LLM 连接失败: {response.get('message')}")
    except:
        print(f"   [FAIL] 无法解析响应: {result.stdout[:200]}")

except subprocess.TimeoutExpired:
    print("   [FAIL] LLM 连接超时（Ollama 可能未启动）")
except Exception as e:
    print(f"   [FAIL] 错误: {e}")

# 3. 测试 LLM 响应速度
print("\n3. 测试 LLM 响应速度...")
try:
    import ollama
    start = time.time()
    response = ollama.chat(
        model='deepseek-r1:8b',
        messages=[{'role': 'user', 'content': 'Reply with just "OK"'}],
        stream=False
    )
    elapsed = time.time() - start
    print(f"   [OK] LLM 响应时间: {elapsed:.2f} 秒")

    if elapsed > 5:
        print(f"   [WARNING] 响应较慢，建议换更快的模型")

except Exception as e:
    print(f"   [FAIL] LLM 调用失败: {e}")

print("\n=== 诊断完成 ===")
print("\n建议:")
print("- 如果抓包失败: 检查网卡选择，用浏览器访问网站产生流量")
print("- 如果 LLM 超时: 运行 'ollama list' 确认模型已下载")
print("- 如果响应慢: 换小模型 'ollama pull qwen2.5:3b'")
