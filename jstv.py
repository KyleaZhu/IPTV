#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jstv.py — 江苏台 HLS 代理

为什么必须本地跑：上游 CDN（litchi-play-encrypted-site.jstv.com）对境外/云厂商出口 IP
直接返回 403，Cloudflare Workers 拿不到流。本机宽带 IP 可以。

用法：
    python jstv.py                 # 监听 0.0.0.0:8080
    python jstv.py --port 9000
    python jstv.py --host 127.0.0.1 # 只允许本机访问

播放地址：
    http://127.0.0.1:8080/2        江苏卫视
    http://127.0.0.1:8080/2.m3u8   同上（部分播放器只认带扩展名的）
    http://127.0.0.1:8080/jsws     用英文代号访问

原理：清单需 txSecret 签名 + Referer，分片只校验 Referer ——
播放器自带的 Referer 一定是它自己的，故分片必须经本进程转发。
"""

import argparse
import base64
import hashlib
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- 配置

PLAY_DOMAIN = "https://litchi-play-encrypted-site.jstv.com"

# 混淆串 slice(6, -3) 后 base64 解码 = '7cSrbhisZe2tF3N3ZGPN'
# 密钥轮换时只改这一处：去 live.jstv.com 首页 JS 搜 txSecret 旁的字符串字面量
KEY_OBF = "L3DC4PN2NTcmJoaXNaZTJ0RjNOM1pHUE4=NKW"
KEY = base64.b64decode(KEY_OBF[6:-3]).decode()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
REFERER = "https://live.jstv.com/"

# 允许转发的上游目录（白名单，替代 jstv.php 里宽松匹配的开放代理）
ALLOWED_DIRS = ("/applive/", "/4klive/")

PLAYLIST_TIMEOUT = 6      # 清单窗口只有 9~12 秒，超时要短
SEGMENT_TIMEOUT = 15

# id -> (名称, 英文代号, 目录)
CHANNELS = {
    "1":  ("江苏卫视4K超高清", "jsws4k", "/4klive/"),
    "2":  ("江苏卫视",         "jsws",   "/applive/"),
    "3":  ("江苏城市",         "jscs",   "/applive/"),
    "4":  ("江苏综艺",         "jszy",   "/applive/"),
    "5":  ("江苏影视",         "jsys",   "/applive/"),
    "6":  ("江苏新闻",         "jsxw",   "/applive/"),
    "7":  ("江苏教育",         "jsjy",   "/applive/"),
    "8":  ("体育休闲",         "jsxx",   "/applive/"),
    "9":  ("优漫卡通",         "ymkt",   "/applive/"),
    "10": ("江苏国际",         "jsgj",   "/applive/"),
}
ALIAS = {en: cid for cid, (_, en, _) in CHANNELS.items()}

_SSL = ssl.create_default_context()


# ---------------------------------------------------------------- 工具

def sign_url(url, expire=300):
    """txSecret = md5(key + 流名 + txTime)，流名为文件名去扩展名。"""
    u = urllib.parse.urlsplit(url)
    stream = u.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    tx_time = format(int(time.time()) + expire, "x")
    secret = hashlib.md5((KEY + stream + tx_time).encode()).hexdigest()
    query = f"txSecret={secret}&txTime={tx_time}"
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, query, ""))


def m3u8_body(text):
    """校验确实是 m3u8（防挑战页/错误 JSON），返回去 BOM 的正文或 None。"""
    if not text:
        return None
    t = text.lstrip("\ufeff").lstrip()
    return text.lstrip("\ufeff") if t.startswith("#EXTM3U") else None


def upstream_ok(url):
    """https + 精确域名 + 目录前缀，挡掉 SSRF。"""
    u = urllib.parse.urlsplit(url)
    return (u.scheme == "https"
            and u.hostname == "litchi-play-encrypted-site.jstv.com"
            and u.path.startswith(ALLOWED_DIRS))


def b64u(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()


def proxy_ref(abs_url):
    return "/s/" + b64u(abs_url)


def resolve(base, rel):
    return urllib.parse.urljoin(base, rel)


def rewrite_playlist(text, base):
    """把分片 / EXT-X-KEY / EXT-X-MAP 全部改写成本进程地址。"""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            out.append(raw)
            continue
        if line.startswith("#"):
            for key in ('URI="', ):
                if key in line:
                    pieces, i = [], 0
                    while True:
                        j = line.find(key, i)
                        if j < 0:
                            pieces.append(line[i:])
                            break
                        k = line.find('"', j + len(key))
                        if k < 0:
                            pieces.append(line[i:])
                            break
                        uri = line[j + len(key):k]
                        pieces.append(line[i:j + len(key)])
                        pieces.append(proxy_ref(resolve(base, uri)))
                        pieces.append('"')
                        i = k + 1
                    line = "".join(pieces)
            out.append(line)
        else:
            out.append(proxy_ref(resolve(base, line)))
    return "\n".join(out) + "\n"


def open_upstream(url, timeout, extra_headers=None):
    headers = {"User-Agent": UA, "Referer": REFERER, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=timeout, context=_SSL)


def build_playlist(cid):
    """取清单；多码率 master 则挑最高 BANDWIDTH 的变体再取一层。"""
    name, en, directory = CHANNELS[cid]
    master = sign_url(f"{PLAY_DOMAIN}{directory}{en}pro.m3u8")
    with open_upstream(master, PLAYLIST_TIMEOUT) as r:
        body = m3u8_body(r.read().decode("utf-8", "replace"))
    if body is None:
        raise RuntimeError("not a playlist")

    base = master
    if "#EXT-X-STREAM-INF" in body.upper():
        best, best_bw, cur_bw = "", -1, 0
        for raw in body.splitlines():
            line = raw.strip()
            if "BANDWIDTH=" in line:
                try:
                    cur_bw = int(line.split("BANDWIDTH=")[1].split(",")[0].split('"')[0])
                except ValueError:
                    cur_bw = 0
                continue
            if line and not line.startswith("#") and cur_bw >= best_bw:
                best_bw, best = cur_bw, resolve(base, line)
        if best:
            base = sign_url(best)
            with open_upstream(base, PLAYLIST_TIMEOUT) as r:
                body = m3u8_body(r.read().decode("utf-8", "replace"))
            if body is None:
                raise RuntimeError("not a playlist")
    return rewrite_playlist(body, base)


def index_text():
    lines = ["# 江苏台 HLS 代理", ""]
    for cid, (name, en, _) in CHANNELS.items():
        lines.append(f"{cid:>2}  {name:<10} /{cid:<3} /{en}")
    lines += ["", "把 /2 或 /2.m3u8 填进播放器即可。"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "jstv/1.0"

    # 关掉逐请求日志噪音，只在出错时打印
    def log_message(self, fmt, *args):
        pass

    def log_error(self, fmt, *args):
        sys.stderr.write("[jstv] %s\n" % (fmt % args))

    def do_GET(self):
        self._route(send_body=True)

    def do_HEAD(self):
        self._route(send_body=False)

    # -- 响应helper

    def _text(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _playlist(self, body):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.apple.mpegurl")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- 路由

    def _route(self, send_body=True):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"

            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return

            if path.startswith("/s/"):
                return self._segment(path[3:], send_body)

            if path == "/":
                return self._text(index_text())

            m = path.lstrip("/")
            if m.endswith(".m3u8"):
                m = m[:-5]
            return self._playlist_route(m)

        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:                     # noqa: BLE001
            self.log_error("处理 %s 失败: %r", self.path, exc)
            try:
                self._text("500 internal error", 500)
            except Exception:
                self.close_connection = True

    def _playlist_route(self, raw_key):
        key = ALIAS.get(raw_key, raw_key)
        if key not in CHANNELS:
            return self._text("404 - 频道不存在，可用: " + ", ".join(CHANNELS), 404)
        try:
            body = build_playlist(key)
        except urllib.error.HTTPError as exc:
            return self._text(f"upstream {exc.code}", 502)
        except Exception as exc:                     # noqa: BLE001
            self.log_error("取清单失败 %s: %r", raw_key, exc)
            return self._text("upstream unreachable", 502)
        self._playlist(body)

    def _segment(self, encoded, send_body=True):
        try:
            abs_url = unb64u(encoded)
        except Exception:                            # noqa: BLE001
            return self._text("bad url encoding", 400)
        if not upstream_ok(abs_url):
            return self._text("bad upstream url", 400)

        extra = {}
        rng = self.headers.get("Range")
        if rng:
            extra["Range"] = rng

        try:
            resp = open_upstream(sign_url(abs_url), SEGMENT_TIMEOUT, extra)
        except urllib.error.HTTPError as exc:
            return self._text(f"upstream {exc.code}", 502)
        except Exception as exc:                     # noqa: BLE001
            self.log_error("取流失败: %r", exc)
            return self._text("upstream unreachable", 502)

        with resp:
            ctype = resp.headers.get("Content-Type", "application/octet-stream")

            # 上游偶尔嵌一层子清单（.m3u8），仍要改写
            if "mpegurl" in ctype.lower() or urllib.parse.urlsplit(abs_url).path.endswith(".m3u8"):
                body = m3u8_body(resp.read().decode("utf-8", "replace"))
                if body is None:
                    return self._text("upstream not playlist", 502)
                return self._playlist(rewrite_playlist(body, abs_url))

            length = resp.headers.get("Content-Length")
            self.send_response(resp.status)
            self.send_header("Content-Type", ctype)
            if length:
                self.send_header("Content-Length", length)
            else:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("Access-Control-Allow-Origin", "*")
            if resp.status == 206:
                self.send_header("Accept-Ranges", "bytes")
                cr = resp.headers.get("Content-Range")
                if cr:
                    self.send_header("Content-Range", cr)
            self.end_headers()
            if send_body and self.command != "HEAD":
                shutil.copyfileobj(resp, self.wfile, 64 * 1024)


def main():
    ap = argparse.ArgumentParser(description="江苏台 HLS 代理（本地）")
    ap.add_argument("--host", default="0.0.0.0", help="监听地址，默认 0.0.0.0（局域网可访问）")
    ap.add_argument("--port", type=int, default=8080, help="监听端口，默认 8080")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                        # noqa: BLE001
            pass

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True

    shown = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    print(f"jstv 代理已启动  http://{shown}:{args.port}")
    print("-" * 46)
    for cid, (name, en, _) in CHANNELS.items():
        print(f"  {name:<10} http://{shown}:{args.port}/{cid}    /{en}")
    print("-" * 46)
    print("  Ctrl+C 停止")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
