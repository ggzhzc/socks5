#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终版：SOCKS5 代理服务，启动时自动生成当前目录下的 list.txt。

功能：
  1. 完整的 SOCKS5 CONNECT 代理（用户名密码认证，IPv4/IPv6/域名）
  2. 启动时自动探测服务器公网 IP，无需手动填写地址
  3. 自动生成 list.txt，包含 socks5:// 与 hysteria2:// 两种链接
  4. 全部使用 Python 标准库，无需 pip 安装任何依赖

环境变量不再使用：所有参数都在脚本开头的「配置区」直接修改。

配置项说明（在配置区修改）：
  HOST            监听地址，默认 0.0.0.0
  PORT            监听端口，默认 1080
  USERNAME        认证用户名，默认 proxyuser
  PASSWORD        认证密码，必填且至少 12 位
  PROXY_HOST      手动指定公网地址（域名或 IP），留空则自动探测
  AUTO_DETECT_IP  True=启动时自动探测公网 IP
  HY2_PASSWORD    设置后额外生成 hysteria2 链接
  HY2_SNI         Hysteria2 的 SNI 域名（可选）
  HY2_INSECURE    链接是否追加 insecure=1（自签证书时用）
  HY2_PORT        Hysteria2 端口

运行（直接）：
  python3 proxy.py

注意：本脚本只实现 SOCKS5 TCP CONNECT；
      Hysteria2 的 UDP 服务需由官方 hysteria 程序监听同一端口的 UDP。
"""

import asyncio
import ipaddress
import logging
import os
import socket
import ssl
import struct
from urllib.parse import quote

# ===========================================================================
# ======================  配置区：请在这里修改参数  ===========================
# ===========================================================================
# 直接改下面这些变量的值即可，无需改动脚本其他部分。
#
# SOCKS5 服务配置
# -------------------------
HOST = "0.0.0.0"            # 监听地址，一般用 0.0.0.0
PORT = 1080                 # 监听端口（常用 1080 / 443）
USERNAME = "proxyuser"      # SOCKS5 用户名
PASSWORD = ""               # SOCKS5 密码（必填，至少12位）

# list.txt 里的服务器地址
# --------------------------------
# 留空（""）则启动时自动探测公网IP；
# 指定域名或IP时则使用你填的值。
PROXY_HOST = ""
AUTO_DETECT_IP = True       # True=启动时自动探测公网IP

# Hysteria 2 链接（可选）
# -------------------------------
HY2_PASSWORD = ""           # 设置后额外生成 hysteria2 链接
HY2_SNI = ""                # Hysteria2 的 SNI 域名（可选）
HY2_INSECURE = False        # True=链接追加 insecure=1（自签证书时用）
HY2_PORT = PORT             # Hysteria2 端口，默认与 SOCKS5 相同

# 其他内部参数（一般不用改）
# -----------------------------------
DETECT_TIMEOUT = 10         # 公网IP探测超时（秒）
LIST_FILE = os.path.join(os.getcwd(), "list.txt")  # 生成的链接文件路径
BUFFER_SIZE = 64 * 1024     # 转发缓冲区大小
# ===========================================================================
# ====================  配置区结束，以下为代码  ===============================
# ===========================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


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

            # 校验它确实是一个 IP，而不是错误页
            ipaddress.ip_address(candidate)
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
# list.txt 生成
# ---------------------------------------------------------------------------

def build_links(public_host: str) -> list:
    """构造要写入 list.txt 的链接。"""
    encoded_user = quote(USERNAME, safe="")
    encoded_password = quote(PASSWORD, safe="")
    host = format_host(public_host)

    links = [f"socks5://{encoded_user}:{encoded_password}@{host}:{PORT}"]

    if HY2_PASSWORD:
        query = []
        if HY2_SNI:
            query.append(f"sni={quote(HY2_SNI, safe='')}")
        if HY2_INSECURE:
            query.append("insecure=1")

        suffix = f"?{'&'.join(query)}" if query else ""
        links.append(
            f"hysteria2://{quote(HY2_PASSWORD, safe='')}@{host}:{HY2_PORT}/{suffix}"
        )

    return links


def write_list_file(public_host: str) -> None:
    """覆盖写入当前目录的 list.txt。"""
    links = build_links(public_host)

    # 敏感文本（密码）写入文件时保持一定的文件权限保护
    content = (
        "# 此文件由 proxy.py 启动时自动生成\n"
        "# 每行一个代理链接，内容含密码，请勿泄露\n"
        + "\n".join(links)
        + "\n"
    )

    with open(LIST_FILE, "w", encoding="utf-8") as file:
        file.write(content)

    try:
        os.chmod(LIST_FILE, 0o600)
    except OSError:
        pass

    logging.info("已生成代理链接文件：%s", LIST_FILE)
    for link in links:
        logging.info("链接：%s", link)


# ---------------------------------------------------------------------------
# SOCKS5 协议实现
# ---------------------------------------------------------------------------

async def read_exactly(reader: asyncio.StreamReader, size: int) -> bytes:
    if size < 0 or size > BUFFER_SIZE:
        raise ValueError("invalid read size")
    return await reader.readexactly(size)


async def send_reply(
    writer: asyncio.StreamWriter,
    code: int,
    host: str = "0.0.0.0",
    port: int = 0,
) -> None:
    """发送 SOCKS5 响应。"""
    try:
        address = ipaddress.ip_address(host)
        address_type = 1 if address.version == 4 else 4
        encoded = bytes([address_type]) + address.packed
    except ValueError:
        encoded_host = host.encode("idna")[:255]
        encoded = b"\x03" + bytes([len(encoded_host)]) + encoded_host

    writer.write(
        b"\x05"
        + bytes([code])
        + b"\x00"
        + encoded
        + struct.pack("!H", port)
    )
    await writer.drain()


async def authenticate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> bool:
    """RFC 1929 用户名密码认证。"""
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


async def read_target(
    reader: asyncio.StreamReader,
) -> tuple:
    """解析 SOCKS5 CONNECT 请求的目标地址。"""
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


async def pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter):
    """单向转发数据，EOF 或异常时结束。"""
    try:
        while True:
            data = await source.read(BUFFER_SIZE)
            if not data:
                break
            destination.write(data)
            await destination.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    remote_writer = None
    peer = writer.get_extra_info("peername")

    try:
        # 1. 方法协商：只接受用户名密码认证（0x02）
        version, method_count = await read_exactly(reader, 2)
        methods = await read_exactly(reader, method_count)
        if version != 5 or 2 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return

        writer.write(b"\x05\x02")
        await writer.drain()

        # 2. 认证
        if not await authenticate(reader, writer):
            logging.warning("认证失败：%s", peer)
            return

        # 3. 读取目标地址
        target_host, target_port = await read_target(reader)
        logging.info("请求 %s -> %s:%s", peer, target_host, target_port)

        # 4. 连接目标
        try:
            remote_reader, remote_writer = await asyncio.open_connection(
                host=target_host,
                port=target_port,
            )
        except ConnectionRefusedError:
            await send_reply(writer, 0x05)  # 连接被拒绝
            return
        except asyncio.TimeoutError:
            await send_reply(writer, 0x04)  # 主机不可达
            return
        except OSError as exc:
            logging.warning("连接目标失败 %s:%s：%s",
                            target_host, target_port, exc)
            await send_reply(writer, 0x01)  # 一般错误
            return

        # 5. 返回成功响应
        bind = remote_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
        await send_reply(writer, 0x00, bind[0], bind[1])

        # 6. 双向转发
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
    if not PASSWORD:
        raise SystemExit("错误：请设置 SOCKS_PASSWORD，不能使用空密码。")
    if len(PASSWORD) < 12:
        raise SystemExit("错误：SOCKS_PASSWORD 至少需要 12 个字符。")

    # 确定写进 list.txt 的公网地址
    if PROXY_HOST:
        public_host = PROXY_HOST
    elif AUTO_DETECT_IP:
        logging.info("正在自动探测公网 IP ...")
        try:
            public_host = await detect_public_ip()
            logging.info("探测到公网 IP：%s", public_host)
        except RuntimeError as exc:
            logging.warning("%s，将使用 127.0.0.1 写入链接。", exc)
            public_host = "127.0.0.1"
    else:
        public_host = "127.0.0.1"

    write_list_file(public_host)

    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
        limit=BUFFER_SIZE,
    )

    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logging.info("SOCKS5 正在监听 TCP：%s", addresses)
    logging.info("用户名：%s", USERNAME)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("服务已停止")
