#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/gatling-setup.log) 2>&1

PROXY_PORT="${proxy_port}"
PROXY_USER="${proxy_user}"
PROXY_PASS="${proxy_pass}"

echo "[*] Gatling - IPv6 Rotating Proxy Setup"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -yq
apt-get install -yq python3 ufw curl net-tools iproute2

echo "[*] Detecting IPv6 network..."

IFACE=$(ip route | awk '/^default/{print $5}' | head -1)
echo "[+] Interface: $${IFACE}"

for i in $(seq 1 20); do
  IPV6_CIDR=$(ip -6 addr show dev "$${IFACE}" scope global \
              | awk '/inet6/{print $2}' | grep -v "^fe80" | head -1)
  [ -n "$${IPV6_CIDR}" ] && break
  echo "[~] Waiting for IPv6... ($${i}/20)"
  sleep 3
done

if [ -z "$${IPV6_CIDR}" ]; then
  echo "[!] No IPv6 address found, aborting."
  exit 1
fi

IPV6_PREFIX=$(python3 -c "
import ipaddress
addr = '$${IPV6_CIDR}'.split('/')[0]
net = ipaddress.IPv6Network(addr + '/64', strict=False)
print(str(net.network_address))
")

echo "[+] IPv6 detected: $${IPV6_CIDR}"
echo "[+] Prefix /64:    $${IPV6_PREFIX}"

echo "[*] Configuring IPv6 /64 rotation..."

cat > /etc/sysctl.d/99-gatling.conf << 'SYSCTLEOF'
net.ipv6.ip_nonlocal_bind = 1
net.ipv6.conf.all.proxy_ndp = 1
net.ipv6.conf.default.proxy_ndp = 1
SYSCTLEOF

sysctl --system -q

ip -6 route add local "$${IPV6_PREFIX}/64" dev lo 2>/dev/null || true
echo "[+] Local route $${IPV6_PREFIX}/64 added"

cat > /etc/rc.local << RCEOF
#!/bin/bash
ip -6 route add local $${IPV6_PREFIX}/64 dev lo 2>/dev/null || true
exit 0
RCEOF
chmod +x /etc/rc.local
systemctl enable rc-local 2>/dev/null || true

echo "[*] Deploying Gatling proxy..."

mkdir -p /opt/gatling /etc/gatling

printf '%s' "$${IPV6_PREFIX}"  > /etc/gatling/prefix
printf '%s' "$${IFACE}"        > /etc/gatling/interface
printf '%s' "$${PROXY_USER}"   > /etc/gatling/user
printf '%s' "$${PROXY_PASS}"   > /etc/gatling/pass
chmod 600 /etc/gatling/user /etc/gatling/pass

cat > /opt/gatling/proxy.py << 'PYEOF'
#!/usr/bin/env python3
"""
Gatling - IPv6 Rotating Proxy
SOCKS5 + HTTP with user:password authentication
Each connection uses a random IPv6 from the /64 block
"""

import asyncio
import base64
import ipaddress
import logging
import os
import random
import socket
import struct
import sys
from urllib.parse import urlparse

log = logging.getLogger("gatling")
log.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s")
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(_fmt)
_fh = logging.FileHandler("/var/log/gatling-proxy.log")
_fh.setFormatter(_fmt)
log.addHandler(_sh)
log.addHandler(_fh)

CFG_DIR = "/etc/gatling"


def read_config(name: str) -> str:
    with open(os.path.join(CFG_DIR, name)) as f:
        return f.read().strip()


def load_config() -> dict:
    prefix = read_config("prefix")
    return {
        "prefix":    prefix,
        "interface": read_config("interface"),
        "user":      read_config("user"),
        "pass":      read_config("pass"),
        "network":   ipaddress.IPv6Network(f"{prefix}/64", strict=False),
    }


def random_ipv6(cfg: dict) -> str:
    rand_host = random.randint(1, (2 ** 64) - 2)
    return str(cfg["network"].network_address + rand_host)


async def resolve_and_connect(host: str, port: int, source_ipv6: str):
    loop = asyncio.get_event_loop()

    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM),
            timeout=5,
        )
        if infos:
            remote_ip = infos[0][4][0]
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    remote_ip, port,
                    local_addr=(source_ipv6, 0),
                    family=socket.AF_INET6,
                ),
                timeout=10,
            )
            return reader, writer, source_ipv6
    except Exception as e:
        log.debug("IPv6 failed for %s: %s", host, e)

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=10,
    )
    return reader, writer, "IPv4-fallback"


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def check_http_auth(headers: list[bytes], cfg: dict) -> bool:
    expected = base64.b64encode(f"{cfg['user']}:{cfg['pass']}".encode()).decode()
    for h in headers:
        txt = h.decode("utf-8", errors="replace").strip()
        if txt.lower().startswith("proxy-authorization:"):
            val = txt.split(":", 1)[1].strip()
            if val.startswith("Basic "):
                if val[6:].strip() == expected:
                    return True
    return False


async def handle_http_connect(reader, writer, target, source_ipv6, http_version):
    host, _, port_str = target.rpartition(":")
    port = int(port_str) if port_str else 443
    try:
        r_reader, r_writer, used_ip = await resolve_and_connect(host, port, source_ipv6)
    except Exception as exc:
        log.warning("HTTP CONNECT %s failed: %s", target, exc)
        writer.write(f"{http_version} 502 Bad Gateway\r\n\r\n".encode())
        await writer.drain()
        return
    log.info("HTTP    %-40s:%-5d  src=%s", host, port, used_ip)
    writer.write(f"{http_version} 200 Connection Established\r\n\r\n".encode())
    await writer.drain()
    await asyncio.gather(pipe(reader, r_writer), pipe(r_reader, writer))


async def handle_http(reader, writer, cfg, first_line):
    source_ipv6 = random_ipv6(cfg)
    peer = writer.get_extra_info("peername")

    try:
        parts = first_line.decode("utf-8", errors="replace").strip().split()
        if len(parts) < 3:
            return
        method, target, http_version = parts

        headers = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if line in (b"\r\n", b"\n", b""):
                break
            headers.append(line)

        if not check_http_auth(headers, cfg):
            log.warning("HTTP AUTH failed from %s", peer)
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"gatling\"\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return

        if method == "CONNECT":
            await handle_http_connect(reader, writer, target, source_ipv6, http_version)
        else:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or 80
            path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

            body = b""
            for h in headers:
                name, _, val = h.decode("utf-8", errors="replace").partition(":")
                if name.strip().lower() == "content-length":
                    cl = int(val.strip())
                    if cl > 0:
                        body = await reader.read(cl)
                    break

            try:
                r_reader, r_writer, used_ip = await resolve_and_connect(host, port, source_ipv6)
            except Exception as exc:
                log.warning("HTTP %s %s failed: %s", method, target, exc)
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return

            log.info("HTTP    %-40s:%-5d  src=%s", host, port, used_ip)

            skip_headers = {"host", "proxy-authorization", "proxy-connection"}
            fwd = b""
            for h in headers:
                key = h.split(b":", 1)[0].decode("utf-8", errors="replace").strip().lower()
                if key not in skip_headers:
                    fwd += h if h.endswith(b"\r\n") else h + b"\r\n"

            request = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n"
            ).encode() + fwd + b"\r\n" + body

            r_writer.write(request)
            await r_writer.drain()

            while True:
                chunk = await r_reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
            r_writer.close()

    except Exception as e:
        log.debug("HTTP error: %s", e)
    finally:
        try:
            writer.close()
        except:
            pass


async def handle_client(reader, writer):
    cfg = load_config()
    try:
        first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=15)
        if first_byte == b"\x05":
            remaining = await reader.readexactly(1)
            nmethods = struct.unpack("!B", remaining)[0]
            methods = await reader.readexactly(nmethods)

            if 2 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x02")
            await writer.drain()

            auth_ver = await reader.readexactly(1)
            if auth_ver != b"\x01":
                return
            ulen = struct.unpack("!B", await reader.readexactly(1))[0]
            username = (await reader.readexactly(ulen)).decode()
            plen = struct.unpack("!B", await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode()

            if username != cfg["user"] or password != cfg["pass"]:
                log.warning("SOCKS5 AUTH failed from %s", writer.get_extra_info("peername"))
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
            await writer.drain()

            source_ipv6 = random_ipv6(cfg)
            req = await reader.readexactly(4)
            ver, cmd, _, atyp = struct.unpack("!BBBB", req)

            if cmd != 1:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            if atyp == 1:
                addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                dlen = struct.unpack("!B", await reader.readexactly(1))[0]
                addr = (await reader.readexactly(dlen)).decode()
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            port = struct.unpack("!H", await reader.readexactly(2))[0]

            try:
                r_reader, r_writer, used_ip = await resolve_and_connect(addr, port, source_ipv6)
            except Exception as e:
                log.warning("SOCKS5 %s:%d failed: %s", addr, port, e)
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            log.info("SOCKS5  %-40s:%-5d  src=%s", addr, port, used_ip)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await asyncio.gather(pipe(reader, r_writer), pipe(r_reader, writer))
        else:
            rest = await reader.readline()
            first_line = first_byte + rest
            await handle_http(reader, writer, cfg, first_line)
    except Exception as e:
        log.debug("Client error: %s", e)
    finally:
        try:
            writer.close()
        except:
            pass


async def main():
    cfg = load_config()
    port = int(os.environ.get("PROXY_PORT", "8080"))
    server = await asyncio.start_server(handle_client, "0.0.0.0", port, limit=2**17)
    log.info("=" * 60)
    log.info("Gatling IPv6 Rotating Proxy")
    log.info("  Prefix /64 : %s/64", cfg["prefix"])
    log.info("  Port       : %d (SOCKS5 + HTTP auto-detect)", port)
    log.info("  Auth       : user/password")
    log.info("=" * 60)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
PYEOF

chmod +x /opt/gatling/proxy.py

echo "[*] Creating systemd service..."

cat > /etc/systemd/system/gatling.service << SVCEOF
[Unit]
Description=Gatling IPv6 Rotating Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/gatling/proxy.py
Restart=always
RestartSec=5
Environment=PROXY_PORT=$${PROXY_PORT}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gatling

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable gatling
systemctl start gatling

echo "[*] Configuring firewall..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow "$${PROXY_PORT}/tcp" comment "Gatling proxy"
ufw --force enable

echo ""
echo "======================================================="
echo "  Gatling installed successfully"
echo "======================================================="
echo "  Prefix /64 : $${IPV6_PREFIX}/64"
echo "  Interface  : $${IFACE}"
echo "  Proxy port : $${PROXY_PORT}"
echo "  Auth       : user/password (SOCKS5 + HTTP)"
echo ""
echo "  Usage with curl (rotating IPv6):"
echo "  curl --socks5-hostname IP:$${PROXY_PORT} --proxy-user USER:PASS URL"
echo "======================================================="
