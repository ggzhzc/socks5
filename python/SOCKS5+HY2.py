#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单端口双协议：Python SOCKS5 (TCP) + sing-box Hysteria2 (UDP)

架构（与主流 sing-box 全家桶脚本一致）：
  TCP <PORT>  →  内置 Python SOCKS5（用户名密码认证，纯 Python 实现）
  UDP <PORT>  →  sing-box 内核实现的 Hysteria2（官方协议实现）

使用：
  1. 编辑下方「配置区」：端口、密码、SNI；
  2. python3 proxy.py
  3. 生成当前目录 list.txt（每行一个明文代理链接）。

依赖：Python 3.9+（仅标准库），服务器需安装 openssl（生成 TLS 证书）。
"""

import asyncio
import ipaddress
import json
import logging
import os
import platform
import shutil
import ssl
import struct
import subprocess
import tarfile
import urllib.request
from urllib.parse import quote

# ===========================================================================
# ======================  配置区：请在这里修改参数  ===========================
# ===========================================================================
# 直接改下面这些变量的值即可，无需改动脚本其他部分。

# ---- 单端口设置（TCP 跑 SOCKS5 转发，UDP 跑 Hysteria2）----
PORT = 443                       # 唯一端口号（<1024 需要 root 权限）
USERNAME = "proxyuser"           # SOCKS5 用户名
PASSWORD = ""                    # SOCKS5 密码（必填，至少 12 位）
HY2_PASSWORD = ""                # Hysteria2 密码（必填，至少 12 位）

# ---- 链接里的服务器地址 ----
PROXY_HOST = ""                  # 留空则自动探测公网 IP；可填域名/IP
AUTO_DETECT_IP = True            # True=启动时自动探测公网 IP

# ---- Hysteria2 TLS（自签证书，客户端链接带 insecure=1）----
HY2_SNI = "bing.com"             # 证书 CN，也作为链接里的 sni 参数
HY2_MASQUERADE = "https://www.bing.com"   # 伪装站点（防主动探测）

# ---- sing-box 内核 ----
SINGBOX_VERSION = "1.11.3"       # 官方 GitHub Release 版本
SINGBOX_DOWNLOAD_URL = ""        # 留空用官方地址；GitHub 下载慢时可填镜像 tar.gz 直链
WORK_DIR = os.path.join(os.getcwd(), ".cache")   # 运行目录（内核/证书/配置）

# ---- 节点名称（可选，出现在链接 # 符号后）----
NAME = ""

# ---- 内部参数（一般不用改）----
DETECT_TIMEOUT = 10              # 公网 IP 探测超时（秒）
LIST_FILE = os.path.join(os.getcwd(), "list.txt")  # 明文链接文件
BUFFER_SIZE = 64 * 1024          # 转发缓冲区大小
# ===========================================================================
# ====================  配置区结束，以下为代码  ===============================
# ===========================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

def run_cmd(args) -> tuple:
    """运行命令，返回 (返回码, 合并输出)。"""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=120
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")
    except Exception as exc:
        return -1, str(exc)


def download_file(url: str, dest: str) -> None:
    """下载文件（跟随重定向）。"""
    request = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (proxy-script)"}
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response, \
                open(dest, "wb") as out:
            shutil.copyfileobj(response, out)
    except Exception as exc:
        raise SystemExit(
            f"下载失败：{exc}\n"
            f"如网络受限，可在配置区设置 SINGBOX_DOWNLOAD_URL 指向镜像地址。"
        ) from exc


# ---------------------------------------------------------------------------
# sing-box 内核：检测架构 → 下载 → 解压
# ---------------------------------------------------------------------------

def ensure_singbox() -> str:
    """确保 sing-box 可执行文件存在，返回其路径。"""
    bin_path = os.path.join(WORK_DIR, "sing-box")

    if os.path.exists(bin_path) and os.access(bin_path, os.X_OK):
        logging.info("sing-box 已存在：%s", bin_path)
        return bin_path

    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        goarch = "amd64"
    elif machine in ("aarch64", "arm64"):
        goarch = "arm64"
    else:
        raise SystemExit(f"不支持的 CPU 架构：{machine}")

    system = platform.system()
    if system == "Linux":
        goos = "linux"
    elif system == "Darwin":
        goos = "darwin"
    else:
        raise SystemExit(f"不支持的操作系统：{system}")

    asset = f"sing-box-{SINGBOX_VERSION}-{goos}-{goarch}.tar.gz"
    if SINGBOX_DOWNLOAD_URL:
        url = SINGBOX_DOWNLOAD_URL
    else:
        url = (
            "https://github.com/SagerNet/sing-box/releases/download/"
            f"v{SINGBOX_VERSION}/{asset}"
        )

    os.makedirs(WORK_DIR, exist_ok=True)
    tar_path = os.path.join(WORK_DIR, asset)

    logging.info("下载 sing-box：%s", url)
    download_file(url, tar_path)

    extracted = extract_singbox(tar_path, WORK_DIR)
    if not extracted:
        raise SystemExit("解压 sing-box 失败，请检查下载文件完整性")

    os.chmod(extracted, 0o755)
    logging.info("sing-box 就绪：%s", extracted)
    return extracted


def extract_singbox(tar_path: str, dest_dir: str):
    """从 tar.gz 中安全解压 sing-box 可执行文件。"""
    try:
        with tarfile.open(tar_path, "r:gz") as archive:
            for member in archive.getmembers():
                name = member.name.replace("\\", "/")
                if name.endswith("/sing-box"):
                    member.name = "sing-box"
                    archive.extract(member, dest_dir)
                    return os.path.join(dest_dir, "sing-box")
    except (tarfile.TarError, OSError) as exc:
        logging.error("解压失败：%s", exc)
    return None


# ---------------------------------------------------------------------------
# TLS 证书：openssl 生成自签证书（CN 取 HY2_SNI）
# ---------------------------------------------------------------------------

def ensure_tls_cert() -> tuple:
    """确保 cert.pem / private.key 存在，返回 (cert_path, key_path)。"""
    cert_path = os.path.join(WORK_DIR, "cert.pem")
    key_path = os.path.join(WORK_DIR, "private.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        logging.info("TLS 证书已存在，跳过生成")
        return cert_path, key_path

    if not shutil.which("openssl"):
        raise SystemExit("未找到 openssl，无法生成 TLS 证书，请先安装。")

    return_code, output = run_cmd([
        "openssl", "ecparam", "-genkey", "-name",
        "prime256v1", "-out", key_path,
    ])
    if return_code != 0:
        raise SystemExit(f"生成私钥失败：{output}")

    return_code, output = run_cmd([
        "openssl", "req", "-new", "-x509", "-days", "3650",
        "-key", key_path, "-out", cert_path,
        "-subj", f"/CN={HY2_SNI}",
    ])
    if return_code != 0:
        raise SystemExit(f"生成证书失败：{output}")

    logging.info("已生成自签 TLS 证书（CN=%s）", HY2_SNI)
    return cert_path, key_path


# ---------------------------------------------------------------------------
# sing-box 配置：Hysteria2 入站（UDP PORT）
# ---------------------------------------------------------------------------

def write_singbox_config(cert_path: str, key_path: str) -> str:
    config = {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "::",
                "listen_port": PORT,
                "users": [
                    {"password": HY2_PASSWORD}
                ],
                "masquerade": HY2_MASQUERADE,
                "tls": {
                    "enabled": True,
                    "server_name": HY2_SNI,
                    "alpn": ["h3"],
                    "certificate_path": cert_path,
                    "key_path": key_path,
                },
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"}
        ],
    }

    config_path = os.path.join(WORK_DIR, "config.json")
    with open(config_path, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)

    logging.info("sing-box 配置已写入：%s", config_path)
    return config_path


# ---------------------------------------------------------------------------
# sing-box 进程管理
# ---------------------------------------------------------------------------

SINGBOX_PROCESSES = []  # [(proc, log_file), ...]


def start_singbox(bin_path: str, config_path: str) -> subprocess.Popen:
    os.makedirs(WORK_DIR, exist_ok=True)
    log_file = open(os.path.join(WORK_DIR, "singbox.log"), "ab", buffering=0)

    proc = subprocess.Popen(
        [bin_path, "run", "-c", config_path],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    SINGBOX_PROCESSES.append((proc, log_file))
    logging.info("sing-box 已启动（PID=%s）", proc.pid)
    return proc


def stop_singbox() -> None:
    for proc, log_file in SINGBOX_PROCESSES:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        log_file.close()
    SINGBOX_PROCESSES.clear()


# ---------------------------------------------------------------------------
# 公网 IP 探测
# ---------------------------------------------------------------------------

async def detect_public_ip() -> str:
    """从多个公网服务探测本机出口 IP。全部失败时抛异常。"""
    endpoints = [
        ("https://api.ipify.org", 443, True),
        ("http://api.ipify.org", 80, False),
        ("http://ifconfig.me/ip", 80, False),
    ]

    for host, port, use_tls in endpoints:
        try:
            ssl_context = ssl.create_default_context() if use_tls else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_context),
                timeout=DETECT_TIMEOUT,
            )

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: proxy-script/1.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()

            data = await asyncio.wait_for(
                reader.read(1024), timeout=DETECT_TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            body = data.split(b"\r\n\r\n", 1)[-1].strip().decode("ascii").strip()
            candidate = body.split("\n", 1)[0].strip()

            ipaddress.ip_address(candidate)  # 校验确实是 IP
            return candidate

        except Exception as exc:
            logging.debug("探测 %s 失败：%s", host, exc)
            continue

    raise RuntimeError("无法自动获取公网 IP，请通过 PROXY_HOST 手动指定")


def format_host(host: str) -> str:
    """IPv6 地址加方括号，适合放进 URI。"""
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


# ---------------------------------------------------------------------------
# 链接生成与文件写入
# ---------------------------------------------------------------------------


def build_links(public_host: str) -> list:
    """构造 list.txt 的代理链接。"""
    host = format_host(public_host)
    fragment = f"#{NAME}" if NAME else ""

    links = [
        f"socks5://{quote(USERNAME, safe='')}:{quote(PASSWORD, safe='')}"
        f"@{host}:{PORT}",
        f"hysteria2://{quote(HY2_PASSWORD, safe='')}@{host}:{PORT}/"
        f"?sni={quote(HY2_SNI, safe='')}&insecure=1&alpn=h3&obfs=none{fragment}",
    ]
    return links


def write_link_file(links: list) -> None:
    """只写入当前目录的 list.txt。"""
    plain = "\n".join(links) + "\n"

    with open(LIST_FILE, "w", encoding="utf-8") as file:
        file.write(
            "# 此文件由 proxy.py 生成，每行一个链接，含密码请勿泄露\n"
            + plain
        )
    try:
        os.chmod(LIST_FILE, 0o600)
    except OSError:
        pass

    logging.info("已生成链接文件：%s（%s 行链接）", LIST_FILE, len(links))
    for link in links:
        logging.info("链接：%s", link)


# ---------------------------------------------------------------------------
# SOCKS5 协议实现（纯 Python，TCP）
# ---------------------------------------------------------------------------

async def read_exactly(reader, size):
    if size < 0 or size > BUFFER_SIZE:
        raise ValueError("invalid read size")
    return await reader.readexactly(size)


async def send_reply(writer, code, host="0.0.0.0", port=0):
    try:
        address = ipaddress.ip_address(host)
        address_type = 1 if address.version == 4 else 4
        encoded = bytes([address_type]) + address.packed
    except ValueError:
        encoded_host = host.encode("idna")[:255]
        encoded = b"\x03" + bytes([len(encoded_host)]) + encoded_host

    writer.write(
        b"\x05" + bytes([code]) + b"\x00" + encoded + struct.pack("!H", port)
    )
    await writer.drain()


async def authenticate(reader, writer):
    version = (await read_exactly(reader, 1))[0]
    if version != 1:
        return False

    username_len = (await read_exactly(reader, 1))[0]
    username = (await read_exactly(reader, username_len)).decode(
        "utf-8", "replace"
    )

    password_len = (await read_exactly(reader, 1))[0]
    password = (await read_exactly(reader, password_len)).decode(
        "utf-8", "replace"
    )

    valid = username == USERNAME and password == PASSWORD
    writer.write(b"\x01\x00" if valid else b"\x01\x01")
    await writer.drain()
    return valid


async def read_target(reader):
    version, command, reserved, address_type = await read_exactly(reader, 4)

    if version != 5 or command != 1 or reserved != 0:
        raise ValueError("仅支持 SOCKS5 CONNECT")

    if address_type == 1:  # IPv4
        host = str(ipaddress.IPv4Address(await read_exactly(reader, 4)))
    elif address_type == 3:  # 域名
        length = (await read_exactly(reader, 1))[0]
        host = (await read_exactly(reader, length)).decode("idna")
    elif address_type == 4:  # IPv6
        host = str(ipaddress.IPv6Address(await read_exactly(reader, 16)))
    else:
        raise ValueError("不支持的地址类型")

    port = struct.unpack("!H", await read_exactly(reader, 2))[0]
    if port == 0:
        raise ValueError("无效的目标端口")

    return host, port


async def pipe(source, destination):
    try:
        while True:
            data = await source.read(BUFFER_SIZE)
            if not data:
                break
            destination.write(data)
            await destination.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass


async def handle_client(reader, writer):
    remote_writer = None
    peer = writer.get_extra_info("peername")

    try:
        version, method_count = await read_exactly(reader, 2)
        methods = await read_exactly(reader, method_count)
        if version != 5 or 2 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return

        writer.write(b"\x05\x02")
        await writer.drain()

        if not await authenticate(reader, writer):
            logging.warning("认证失败：%s", peer)
            return

        target_host, target_port = await read_target(reader)
        logging.info("请求 %s -> %s:%s", peer, target_host, target_port)

        try:
            remote_reader, remote_writer = await asyncio.open_connection(
                host=target_host,
                port=target_port,
            )
        except ConnectionRefusedError:
            await send_reply(writer, 0x05)
            return
        except asyncio.TimeoutError:
            await send_reply(writer, 0x04)
            return
        except OSError as exc:
            logging.warning(
                "连接目标失败 %s:%s：%s", target_host, target_port, exc
            )
            await send_reply(writer, 0x01)
            return

        bind = remote_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
        await send_reply(writer, 0x00, bind[0], bind[1])

        first = asyncio.create_task(pipe(reader, remote_writer))
        second = asyncio.create_task(pipe(remote_reader, writer))
        await asyncio.wait([first, second], return_when=asyncio.FIRST_COMPLETED)
        first.cancel()
        second.cancel()
        await asyncio.gather(first, second, return_exceptions=True)

    except (asyncio.IncompleteReadError, ConnectionError, ValueError,
            UnicodeError, socket.gaierror):
        pass
    except Exception:
        logging.exception("处理客户端失败：%s", peer)
    finally:
        if remote_writer is not None:
            remote_writer.close()
            await remote_writer.wait_closed()
        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

async def main() -> None:
    # 校验配置
    if not PASSWORD or len(PASSWORD) < 12:
        raise SystemExit("错误：请在配置区设置 ≥12 位的 SOCKS5 PASSWORD。")
    if not HY2_PASSWORD or len(HY2_PASSWORD) < 12:
        raise SystemExit("错误：请在配置区设置 ≥12 位的 HY2_PASSWORD。")

    # 确定写进链接的公网地址
    if PROXY_HOST:
        public_host = PROXY_HOST
    elif AUTO_DETECT_IP:
        logging.info("正在自动探测公网 IP ...")
        try:
            public_host = await detect_public_ip()
            logging.info("探测到公网 IP：%s", public_host)
        except RuntimeError as exc:
            logging.warning("%s，将用 127.0.0.1 写入链接。", exc)
            public_host = "127.0.0.1"
    else:
        public_host = "127.0.0.1"

    # 生成链接文件
    write_link_file(build_links(public_host))

    # 准备 sing-box（UDP Hysteria2）
    if WORK_DIR:
        os.makedirs(WORK_DIR, exist_ok=True)
    bin_path = ensure_singbox()
    cert_path, key_path = ensure_tls_cert()
    config_path = write_singbox_config(cert_path, key_path)
    start_singbox(bin_path, config_path)

    # 启动 Python SOCKS5（TCP）
    server = await asyncio.start_server(
        handle_client, "0.0.0.0", PORT, limit=BUFFER_SIZE
    )
    addresses = ", ".join(str(s.getsockname()) for s in server.sockets)
    logging.info("SOCKS5 (TCP) 正在监听：%s", addresses)
    logging.info("用户名：%s", USERNAME)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("收到退出信号，停止 sing-box ...")
        stop_singbox()
        logging.info("已停止。")
