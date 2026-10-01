#!/usr/bin/env python3
# socks5.py
import socket
import struct
import select
import threading
import sys

# ---------------- 配置 ----------------
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 25813          # 改成你实际用的端口
BUFFER_SIZE = 4096
TIMEOUT = 60

# 用户名密码认证，留空表示不认证
USERNAME = "改成你的用户名"
PASSWORD = "改成你的强密码"

# 日志开关
VERBOSE = False              # False = 不打印任何日志
# --------------------------------------

SOCKS_VERSION = 5

# 认证方式
AUTH_NO_AUTH = 0x00
AUTH_USERPASS = 0x02
AUTH_NO_ACCEPT = 0xFF

# 命令
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP = 0x03

# 地址类型
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# 回复码
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NET_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


def log(msg):
    """统一日志出口，VERBOSE=False 时什么都不打印"""
    if VERBOSE:
        print(msg, flush=True)


def recv_exact(sock, n):
    """精确接收 n 个字节"""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_client(client):
    try:
        client.settimeout(TIMEOUT)

        # ---- 1. 握手：客户端版本 + 认证方法 ----
        header = recv_exact(client, 2)
        if not header:
            return
        version, nmethods = header[0], header[1]
        if version != SOCKS_VERSION:
            return
        methods = recv_exact(client, nmethods)
        if methods is None:
            return

        # 选择认证方式
        if USERNAME:
            if AUTH_USERPASS not in methods:
                client.sendall(bytes([SOCKS_VERSION, AUTH_NO_ACCEPT]))
                return
            client.sendall(bytes([SOCKS_VERSION, AUTH_USERPASS]))
            if not do_userpass_auth(client):
                return
        else:
            if AUTH_NO_AUTH not in methods:
                client.sendall(bytes([SOCKS_VERSION, AUTH_NO_ACCEPT]))
                return
            client.sendall(bytes([SOCKS_VERSION, AUTH_NO_AUTH]))

        # ---- 2. 请求：命令 + 目标地址 ----
        request = recv_exact(client, 4)
        if not request:
            return
        ver, cmd, rsv, atyp = request

        if cmd != CMD_CONNECT:
            send_reply(client, REP_CMD_NOT_SUPPORTED)
            return

        # 解析目标地址
        if atyp == ATYP_IPV4:
            raw = recv_exact(client, 4)
            if raw is None:
                return
            dst_addr = socket.inet_ntoa(raw)
        elif atyp == ATYP_DOMAIN:
            length_raw = recv_exact(client, 1)
            if length_raw is None:
                return
            length = length_raw[0]
            domain = recv_exact(client, length)
            if domain is None:
                return
            try:
                dst_addr = domain.decode("idna")
            except UnicodeError:
                dst_addr = domain.decode("utf-8", errors="ignore")
        elif atyp == ATYP_IPV6:
            raw = recv_exact(client, 16)
            if raw is None:
                return
            dst_addr = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            send_reply(client, REP_ATYP_NOT_SUPPORTED)
            return

        port_raw = recv_exact(client, 2)
        if port_raw is None:
            return
        dst_port = struct.unpack("!H", port_raw)[0]

        log(f"[+] CONNECT {dst_addr}:{dst_port}")

        # ---- 3. 连接目标 ----
        try:
            remote = socket.create_connection((dst_addr, dst_port), timeout=TIMEOUT)
        except socket.gaierror:
            send_reply(client, REP_HOST_UNREACHABLE)
            return
        except ConnectionRefusedError:
            send_reply(client, REP_CONN_REFUSED)
            return
        except OSError:
            send_reply(client, REP_NET_UNREACHABLE)
            return

        send_reply(client, REP_SUCCESS)
        remote.settimeout(TIMEOUT)

        # ---- 4. 双向转发 ----
        relay(client, remote)

    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log(f"[!] 处理客户端出错: {type(e).__name__}: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def do_userpass_auth(client):
    """用户名密码认证 (RFC 1929)"""
    header = recv_exact(client, 2)
    if not header:
        return False
    ver, ulen = header
    if ver != 0x01:
        return False
    uname = recv_exact(client, ulen)
    if uname is None:
        return False
    plen_raw = recv_exact(client, 1)
    if plen_raw is None:
        return False
    plen = plen_raw[0]
    passwd = recv_exact(client, plen)
    if passwd is None:
        return False

    if uname.decode(errors="ignore") == USERNAME and passwd.decode(errors="ignore") == PASSWORD:
        client.sendall(bytes([0x01, 0x00]))
        return True
    else:
        client.sendall(bytes([0x01, 0x01]))
        return False


def send_reply(client, rep, atyp=ATYP_IPV4, addr="0.0.0.0", port=0):
    """发送 SOCKS5 回复"""
    try:
        if atyp == ATYP_IPV4:
            addr_bytes = socket.inet_aton(addr)
        elif atyp == ATYP_IPV6:
            addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
        else:
            addr_bytes = socket.inet_aton("0.0.0.0")
        reply = struct.pack("!BBBB", SOCKS_VERSION, rep, 0x00, atyp) + addr_bytes + struct.pack("!H", port)
        client.sendall(reply)
    except Exception:
        pass


def relay(a, b):
    """双向转发数据"""
    sockets = [a, b]
    while True:
        try:
            readable, _, _ = select.select(sockets, [], [], TIMEOUT)
        except (ValueError, OSError):
            break
        if not readable:
            break
        for s in readable:
            other = b if s is a else a
            try:
                data = s.recv(BUFFER_SIZE)
            except (socket.timeout, ConnectionResetError, OSError):
                return
            if not data:
                return
            try:
                other.sendall(data)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(128)

    print("Server started.", flush=True)

    try:
        while True:
            client, addr = server.accept()
            log(f"[+] 新连接: {addr[0]}:{addr[1]}")
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    main()
