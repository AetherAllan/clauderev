#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
claude_location_benchmark.py
============================

Claude Desktop / Claude CLI —— macOS「位置与身份探测」全量 Benchmark。

这个脚本不"猜测"Claude 怎么定位你。每一个探针（probe）都对应一份已逆向出来的
客户端代码，脚本按客户端的**原始逻辑**在本机重放同一次读取，然后报告：

  · 本机实际会读出什么（value）
  · 这个值被客户端送到哪里去（channel：telemetry / HTTP header / prompt / 磁盘）
  · 它作为位置或身份信号的风险等级（status：OK / RISK / CRIT / INFO / SKIP）

约定
----
  [观测]  直接从代码 / 二进制 / 本机命令输出读到的事实
  [推断]  基于 [观测] 的合理外推
  [不可判定] 静态分析无法确定（例如服务端如何加权打分）

只读：脚本不写任何系统状态，不修改 Claude 的任何文件，不注入、不 hook。
唯一的出站流量是公开的 IP 回显 / 地理查询，以及（默认开启，可用 --offline 或
--no-anthropic 关闭）一次 /api/hello 边缘探测。

用法
----
  python3 tools/claude_location_benchmark.py                  # 全量，输出 md + json
  python3 tools/claude_location_benchmark.py --offline        # 跳过所有网络探针
  python3 tools/claude_location_benchmark.py --no-anthropic   # 只跳过 /api/hello
  python3 tools/claude_location_benchmark.py --no-keychain    # 不碰 Keychain
  python3 tools/claude_location_benchmark.py --verbose        # 打印每个探针细节
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

HOME = Path.home()
IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform.startswith("win")

UA = "claude-location-benchmark/1.0 (+static-analysis)"

# 状态语义
OK = "OK"        # 无泄漏 / 一致
RISK = "RISK"    # 可被用于定位或跨账号关联
CRIT = "CRIT"    # 明确矛盾或强标识（时区<>出口IP / 数据中心IP / 残留身份文件）
INFO = "INFO"    # 仅观测，本身不构成信号
SKIP = "SKIP"    # 未安装 / 平台不支持 / 被禁用

STATUS_ORDER = {CRIT: 0, RISK: 1, INFO: 2, OK: 3, SKIP: 4}
STATUS_WEIGHT = {CRIT: 10, RISK: 4, INFO: 0, OK: 0, SKIP: 0}

GROUPS = [
    ("A", "设备身份锚点"),
    ("B", "硬件与系统指纹"),
    ("C", "语言 / 区域 / 时区"),
    ("D", "网络出口与地理"),
    ("E", "本地残留"),
    ("F", "Claude CLI 专属"),
    ("G", "一致性判定与评分"),
]
GROUP_TITLE = dict(GROUPS)


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------

def sh(cmd: list[str], timeout: float = 10.0) -> tuple[int, str, str]:
    """跑一个 argv，永不抛异常。"""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return (
            p.returncode,
            (p.stdout or b"").decode("utf-8", "replace"),
            (p.stderr or b"").decode("utf-8", "replace"),
        )
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def out(cmd: list[str], timeout: float = 10.0) -> str:
    rc, stdout, _ = sh(cmd, timeout)
    return stdout if rc == 0 else ""


def read_bytes(p: Path) -> Optional[bytes]:
    try:
        return p.read_bytes()
    except Exception:  # noqa: BLE001
        return None


def read_text(p: Path, limit: int = 4_000_000) -> Optional[str]:
    try:
        with open(p, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def load_json(p: Path) -> Any:
    t = read_text(p)
    if t is None:
        return None
    try:
        return json.loads(t)
    except Exception:  # noqa: BLE001
        return None


def read_plist(p: Path) -> Any:
    b = read_bytes(p)
    if b is None:
        return None
    try:
        return plistlib.loads(b)
    except Exception:  # noqa: BLE001
        return None


def path_state(p: Path) -> tuple[str, str]:
    """返回 (状态, 描述)。不跟随可疑符号链接。"""
    try:
        if p.is_symlink():
            target = os.readlink(p)
            if p.exists():
                return "symlink", target
            return "broken-symlink", target
        if p.is_dir():
            n = 0
            sz = 0
            for root, _dirs, files in os.walk(p):
                for f in files:
                    n += 1
                    try:
                        sz += os.lstat(os.path.join(root, f)).st_size
                    except OSError:
                        pass
                if n > 20000:
                    break
            return "dir", f"{n} files, {human(sz)}"
        if p.is_file():
            return "file", human(p.stat().st_size)
    except PermissionError:
        return "no-permission", ""
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)
    return "absent", ""


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024.0
    return f"{n:.0f}TB"


def http(url: str, timeout: float = 8.0, headers: Optional[dict] = None) -> tuple[int, dict, str]:
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200_000).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200_000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as exc:  # noqa: BLE001
        return 0, {}, f"error: {exc}"


def http_json(url: str, timeout: float = 8.0) -> Any:
    code, _h, body = http(url, timeout)
    if code != 200:
        return None
    try:
        return json.loads(body)
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------
# 复刻的客户端逻辑（逐条对应逆向出来的函数）
# --------------------------------------------------------------------------

def device_class(total_bytes: Optional[int]) -> Optional[str]:
    """复刻 index.chunk-BfOAx4v9.js: MVt(e) + NVt=MVt(os.totalmem())"""
    if total_bytes is None:
        return None
    if total_bytes < 6e9:
        return "le4"
    if total_bytes < 12e9:
        return "8"
    if total_bytes < 2e10:
        return "16"
    return "gt16"


def total_memory_bytes() -> Optional[int]:
    if IS_MAC:
        s = out(["sysctl", "-n", "hw.memsize"], 5).strip()
        if s.isdigit():
            return int(s)
    try:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except Exception:  # noqa: BLE001
        return None


def yur(langs: list[str]) -> list[str]:
    """复刻 index.chunk-BfOAx4v9.js@4140347  function YUr(e)"""
    acc: list[str] = []
    for n in langs:
        head = re.split(r"[.@]", n, maxsplit=1)[0]
        head = head.replace("_", "-")
        if head in ("", "C", "POSIX") or head in acc:
            continue
        acc.append(head)
    return acc


def ist_sanitize(s: str) -> str:
    """复刻 anthropic-device-id 的清洗函数 Ist(e)"""
    cleaned = re.sub(r"[^\x20-\x7E]", "", s or "")
    return cleaned if cleaned else "invalid"


TZ_RE = re.compile(r"zoneinfo/(.+)$")


def resolved_timezone() -> tuple[str, str]:
    """近似 Intl.DateTimeFormat().resolvedOptions().timeZone（Node 先看 TZ 环境变量）"""
    env_tz = os.environ.get("TZ")
    if env_tz:
        return env_tz, "env:TZ"
    for link in ("/etc/localtime", "/var/db/timezone/localtime"):
        try:
            if os.path.islink(link):
                tgt = os.readlink(link)
                m = TZ_RE.search(tgt)
                if m:
                    return m.group(1), link
        except Exception:  # noqa: BLE001
            pass
    s = out(["/usr/sbin/systemsetup", "-gettimezone"], 6)
    m = re.search(r"Time Zone:\s*(\S+)", s)
    if m:
        return m.group(1), "systemsetup"
    try:
        import time
        return time.tzname[0], "tzname-fallback"
    except Exception:  # noqa: BLE001
        return "unknown", "unknown"


def utc_offset_hours(tzname: str) -> Optional[float]:
    try:
        from zoneinfo import ZoneInfo
        from datetime import timedelta  # noqa: F401
        off = datetime.now(ZoneInfo(tzname)).utcoffset()
        return off.total_seconds() / 3600.0 if off is not None else None
    except Exception:  # noqa: BLE001
        return None


# --- 四个 VPN 探针（逐字复刻）--------------------------------------------

def probe_vpn_ifaces() -> list[str]:
    """I2r(): /sbin/ifconfig  →  ^(utun\\d+|ppp\\d+|ipsec\\d+|tun\\d+):"""
    s = out(["/sbin/ifconfig"], 8)
    hits = re.findall(r"^(utun\d+|ppp\d+|ipsec\d+|tun\d+):", s, re.M)
    return list(dict.fromkeys(hits))


def probe_scutil_connected() -> list[str]:
    """L2r(): /usr/sbin/scutil --nc list  →  连接中的 VPN 服务名"""
    s = out(["/usr/sbin/scutil", "--nc", "list"], 8)
    acc: list[str] = []
    for m in re.finditer(r'^[^\S\n]*\*\s*\(Connected\).*"([^"]+)"', s, re.M):
        if m.group(1):
            acc.append(m.group(1))
    return acc


def probe_bootpd() -> bool:
    """R2r(): pgrep -x bootpd"""
    return bool(out(["/usr/bin/pgrep", "-x", "bootpd"], 5).strip())


def probe_bridge_vmnet() -> list[str]:
    """z2r(): ifconfig -a  →  ^(bridge\\d+|vmnet\\d+):"""
    s = out(["/sbin/ifconfig", "-a"], 8)
    return list(dict.fromkeys(re.findall(r"^(bridge\d+|vmnet\d+):", s, re.M)))


# --- 全局偏好 -------------------------------------------------------------

def global_defaults() -> dict:
    rc, stdout, _ = sh(["defaults", "export", "-g", "-"], 10)
    if rc == 0:
        try:
            return plistlib.loads(stdout.encode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            pass
    d: dict[str, Any] = {}
    for key in ("AppleLanguages", "AppleLocale"):
        s = out(["defaults", "read", "-g", key], 6)
        if s.strip():
            vals = re.findall(r'"([^"]+)"', s)
            d[key] = vals if vals else s.strip()
    return d


# --- 数据中心 vs 住宅网段 ------------------------------------------------

DC_PATTERNS = [
    (r"(?i)\b(dmit)\b", "DMIT"),
    (r"(?i)\b(digitalocean)\b", "DigitalOcean"),
    (r"(?i)\b(vultr|choopa)\b", "Vultr"),
    (r"(?i)\b(linode|akamai)\b", "Linode/Akamai"),
    (r"(?i)\b(ovh|kimsufi|soyoustart)\b", "OVH"),
    (r"(?i)\b(hetzner)\b", "Hetzner"),
    (r"(?i)\b(contabo)\b", "Contabo"),
    (r"(?i)\b(leaseweb)\b", "Leaseweb"),
    (r"(?i)\b(m247)\b", "M247"),
    (r"(?i)\b(racknerd|colocrossing|psychz|quadranet|hostkey|buyvm|frantech)\b", "budget-VPS"),
    (r"(?i)\b(amazon|aws)\b", "AWS"),
    (r"(?i)\b(google|gcp)\b", "Google Cloud"),
    (r"(?i)\b(microsoft|azure)\b", "Azure"),
    (r"(?i)\b(oracle)\b", "Oracle Cloud"),
    (r"(?i)\b(alibaba|aliyun|tencent)\b", "CN-cloud"),
    (r"(?i)\b(cloud services|cloud hosting|hosting|datacenter|data center|"
     r"dedicated server|vps|virtual server|colocation|colo)\b", "hosting-keyword"),
]


def classify_asn(org: str, isp: str = "") -> tuple[bool, str]:
    blob = f"{org} {isp}"
    for pat, name in DC_PATTERNS:
        if re.search(pat, blob):
            return True, name
    return False, ""


# --------------------------------------------------------------------------
# 结果模型
# --------------------------------------------------------------------------

@dataclass
class Probe:
    pid: str
    group: str
    title: str
    source: str      # 代码出处
    channel: str     # 值流向哪里
    risk: str        # 泄漏 / 关联含义
    status: str = INFO
    value: Any = None
    note: str = ""
    evidence: str = ""   # 原始命令输出片段
    weight: Optional[int] = None   # None = 按状态默认权重；0 = 汇总项不计分


class Bench:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.results: list[Probe] = []
        self.cache: dict[str, Any] = {}
        self.facts: dict[str, Any] = {}   # 供一致性分析使用的结构化事实

    # ---- 收录 ----
    def add(
        self,
        pid: str,
        group: str,
        title: str,
        source: str,
        channel: str,
        risk: str,
        status: str,
        value: Any = None,
        note: str = "",
        evidence: str = "",
        weight: Optional[int] = None,
    ) -> Probe:
        p = Probe(pid, group, title, source, channel, risk, status, value, note,
                  evidence, weight)
        self.results.append(p)
        return p

    # ---- A 设备身份 ----
    def group_a(self) -> None:
        g = "A"

        # A01/A02 userData 解析
        user_data_env = os.environ.get("CLAUDE_USER_DATA_DIR")
        user_data = HOME / "Library" / "Application Support" / "Claude"
        if user_data_env:
            user_data = Path(user_data_env)
        self.facts["user_data"] = str(user_data)

        st, desc = path_state(user_data)
        self.add(
            "A01", g, "userData 目录（ant-did / config.json / window-state.json 的家）",
            "index.pre.js UQ() + app.getPath('userData')",
            "磁盘：所有持久身份文件的根",
            "目录存在即说明该机器装过并用过桌面端；里面的 ant-did 是长期设备标识",
            OK if st == "absent" else RISK,
            f"{user_data} → {st} ({desc})",
            note="" if st == "absent" else "该目录下的 ant-did 必须单独删除",
        )
        if user_data_env:
            self.add(
                "A02", g, "CLAUDE_USER_DATA_DIR 覆盖",
                "index.pre.js UQ() 第一分支",
                "磁盘路径重定向",
                "会把 userData 搬到自定义位置，常规清理脚本会漏掉",
                RISK, user_data_env,
            )
        else:
            self.add(
                "A02", g, "CLAUDE_USER_DATA_DIR 覆盖",
                "index.pre.js UQ() 第一分支",
                "磁盘路径重定向",
                "未设置 → userData 走默认路径",
                OK, "(未设置)",
            )

        # A03 ant-did
        ant_did = user_data / "ant-did"
        st, desc = path_state(ant_did)
        val: Any = None
        note = ""
        if st == "file":
            raw = (read_text(ant_did) or "").strip()
            try:
                import base64 as _b64
                decoded = _b64.b64decode(raw + "==", validate=False).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                decoded = "(base64 解码失败)"
            val = {
                "path": str(ant_did),
                "raw": raw,
                "decoded": decoded,
                "as_anthropic-device-id": ist_sanitize(raw),
            }
            try:
                mode = oct(ant_did.stat().st_mode & 0o777)
                nlink = ant_did.stat().st_nlink
            except Exception:  # noqa: BLE001
                mode, nlink = "?", "?"
            note = f"mode={mode} nlink={nlink}（客户端要求 0o600 且必须是普通文件）"
        elif st == "absent":
            note = "不存在 → 下次启动会用 flag:'wx' 新建一个 randomUUID"
        else:
            note = f"异常状态：{desc}（客户端会 throw 'ant-did is not a plain file'）"
        self.add(
            "A03", g, "ant-did 设备标识",
            "index.chunk-BfOAx4v9.js KVt() @2045945",
            "HTTP header anthropic-device-id + GrowthBook + OAuth authorize",
            "这是桌面端最稳定的设备指纹；跨账号不变即可被关联",
            OK if st == "absent" else CRIT,
            val if val else f"{ant_did} → {st}",
            note=note,
        )

        # A04/A05/A06 ~/.claude.json
        cj = HOME / ".claude.json"
        st, desc = path_state(cj)
        data = load_json(cj) if st == "file" else None
        if isinstance(data, dict):
            self.cache["claude_json"] = data
            hex_re = re.compile(r"^[0-9a-f]{64}$")
            for pid, key, why in (
                ("A04", "userID", "服务端用它把不同 session / 设备归到同一个人"),
                ("A05", "machineID", "整机标识，重装 CLI 不会变"),
            ):
                v = data.get(key)
                ok = bool(v and hex_re.match(str(v)))
                self.add(
                    pid, g, f"~/.claude.json → {key}",
                    "CLI: function h0()/FSt() + var Fs=/^[0-9a-f]{64}$/",
                    "CLI 身份上行（rollout / telemetry / 设备注册）",
                    why,
                    CRIT if ok else INFO,
                    v if v else "(缺失)",
                    note="64-hex 合法" if ok else "缺失或格式不符（客户端会重新生成）",
                )
            oa = data.get("oauthAccount")
            if isinstance(oa, dict):
                shown = {k: oa.get(k) for k in ("emailAddress", "organizationUuid",
                                                "accountUuid", "organizationRole")
                         if k in oa}
                self.add(
                    "A06", g, "~/.claude.json → oauthAccount",
                    "CLI: 84 处引用；desktop: auth.organization_uuid / account_uuid",
                    "telemetry auth 块 + Cowork 设备注册",
                    "账号锚点：清掉它才能切断新账号与旧账号的本地联系",
                    CRIT, shown or "(空对象)",
                )
            else:
                self.add(
                    "A06", g, "~/.claude.json → oauthAccount",
                    "CLI: 84 处引用", "telemetry auth 块", "账号锚点",
                    OK, "(缺失 → 尚未登录或已登出)",
                )
            known = [
                "userID", "machineID", "oauthAccount", "projects", "mcpServers",
                "githubRepoPaths", "customApiKeyResponses", "pastedContents",
                "numStartups", "installMethod", "tipsHistory",
                "hasCompletedOnboarding", "lastOnboardingVersion",
                "migrationVersion", "cachedChangelog", "changelogLastFetched",
                "autoUpdates",
            ]
            present = [k for k in known if k in data]
            extra = sorted(set(data) - set(known))
            self.add(
                "A07", g, "~/.claude.json 字段盘点",
                "CLI 字符串命中统计",
                "本地状态（部分上行，例如 githubRepoPaths）",
                "githubRepoPaths 若上行，会把你的代码仓库路径一起带走",
                RISK if present else OK,
                {"present": present, "unknown_extra": extra[:40],
                 "project_count": len(data.get("projects") or {})},
            )
        else:
            for pid, key in (("A04", "userID"), ("A05", "machineID"), ("A06", "oauthAccount")):
                self.add(
                    pid, g, f"~/.claude.json → {key}",
                    "CLI 身份持久化", "CLI 身份上行", "账号/整机锚点",
                    OK, f"{cj} → {st}",
                )
            self.add(
                "A07", g, "~/.claude.json 字段盘点",
                "CLI 字符串命中统计", "本地状态", "账号/整机锚点",
                OK, f"{cj} → {st}",
            )

        # A08 CLI 设备密钥
        dk = HOME / ".claude" / ".device-keys"
        st, desc = path_state(dk)
        self.add(
            "A08", g, "CLI 设备私钥文件 ~/.claude/.device-keys",
            "CLI: C='Claude Code-device-keys' / J={privateKeyPkcs8B64,rowPk} / prime256v1",
            "client_attestation（ECDSA P-256, dsaEncoding=ieee-p1363）",
            "登录期真设备证明：私钥在则服务端认得这台机器；删了才能生成新设备行",
            OK if st == "absent" else CRIT,
            f"{dk} → {st} ({desc})",
        )

        # A09 Keychain
        if self.args.keychain and IS_MAC:
            svc = "Claude Code-device-keys"
            rc, stdout, _ = sh(["security", "find-generic-password", "-s", svc], 8)
            self.add(
                "A09", g, f"Keychain 条目「{svc}」",
                "CLI: lke()/dke()/cke 凭据存储命名",
                "设备私钥落盘位置（macOS Keychain）",
                "存在即代表旧设备行仍可被本机复活",
                OK if rc != 0 else CRIT,
                "存在" if rc == 0 else "不存在",
                note="security find-generic-password 仅读元数据，不取密码",
            )
        else:
            self.add(
                "A09", g, "Keychain 条目「Claude Code-device-keys」",
                "CLI 凭据存储", "设备私钥", "旧设备行可被复活",
                SKIP, "(已用 --no-keychain 或非 macOS 跳过)",
            )

    # ---- B 硬件与系统 ----
    def group_b(self) -> None:
        g = "B"

        sv = read_plist(Path("/System/Library/CoreServices/SystemVersion.plist")) or {}
        os_version = sv.get("ProductVersion")
        os_build = sv.get("ProductBuildVersion")
        self.facts["os_build"] = os_build

        self.add(
            "B01", g, "os_build（ProductBuildVersion）",
            "index.chunk-BfOAx4v9.js bO(): 读 SystemVersion.plist 的 ProductBuildVersion",
            "telemetry os_build + Sentry os.build",
            "精确 build 号是强机器归类特征（非地理，但可做设备相关）",
            INFO, os_build,
        )
        self.add(
            "B02", g, "os_version（ProductVersion）",
            "process.getSystemVersion()",
            "HTTP header anthropic-os-version + telemetry os_version",
            "版本组合可缩小人群",
            INFO, os_version,
        )
        self.add(
            "B03", g, "os_release（内核）",
            "os.release()",
            "telemetry os_release",
            "同上",
            INFO, out(["uname", "-r"], 5).strip(),
        )

        cpu = out(["sysctl", "-n", "machdep.cpu.brand_string"], 5).strip()
        if not cpu:
            sp = out(["system_profiler", "SPHardwareDataType"], 25)
            m = re.search(r"^\s*(?:Chip|Processor Name):\s*(.+)$", sp, re.M)
            if m:
                cpu = m.group(1).strip()
        if not cpu:
            cpu = out(["sysctl", "-n", "hw.model"], 5).strip()
        self.add(
            "B04", g, "cpu_model",
            "index.chunk-BfOAx4v9.js VEn(): os.cpus()[0].model",
            "telemetry cpu_model + Sentry device.cpu_description",
            "机型越具体，人群越小",
            RISK if cpu else INFO, cpu or "(读不到)",
        )

        self.facts["cpu_model"] = cpu
        mem = total_memory_bytes()
        self.facts["total_mem"] = mem
        self.add(
            "B05", g, "total_memory_gb",
            "index.chunk-BfOAx4v9.js PVt = Math.round(os.totalmem()/1024**3)",
            "HTTP header anthropic-total-memory-gb",
            "与其他 header 组合成准指纹",
            INFO,
            (round(mem / 1024 ** 3) if mem else None),
            note=f"原始 {mem} bytes" if mem else "",
        )

        dc = device_class(mem)
        self.facts["device_class"] = dc
        self.add(
            "B06", g, "device_class",
            "index.chunk-BfOAx4v9.js MVt() → NVt → header/telemetry/argv 三处",
            "header anthropic-device-class + telemetry + preload argv",
            "只有 4 档（le4/8/16/gt16），区分度低",
            INFO, dc,
            note="<6GB→le4, <12GB→8, <20GB→16, 其余→gt16",
        )

        translated = out(["sysctl", "-n", "sysctl.proc_translated"], 5).strip()
        self.add(
            "B07", g, "running_under_translation（Rosetta）",
            "app.runningUnderARM64Translation",
            "telemetry running_under_translation",
            "Rosetta 标记是少见的硬件/软件组合特征",
            INFO,
            {"proc_translated": translated or "(无此项，非 arm64 或不支持)",
             "machine_arch": out(["uname", "-m"], 5).strip()},
        )

        win_store = os.environ.get("windowsStore")
        self.add(
            "B08", g, "installer_variant / store_build",
            "index.chunk-BfOAx4v9.js Mfe()/Pfe(): $r(){return !1}",
            "telemetry installer_variant + store_build:!1",
            "本构建里 $r() 硬编码 false → 恒为 squirrel，无区分度",
            INFO,
            {"isMsix": bool(win_store), "installer_variant": "msix" if win_store else "squirrel",
             "store_build": False},
        )

        self.add(
            "B09", g, "platform / arch",
            "process.platform / process.arch",
            "header anthropic-os-platform + telemetry",
            "粗粒度",
            INFO, {"platform": sys.platform, "arch": out(["uname", "-m"], 5).strip()},
        )

        # 更强的硬件标识：客户端没读，但系统里有 —— 属于"服务端可要求、本机已有"
        ioreg = out(["ioreg", "-d2", "-c", "IOPlatformExpertDevice"], 20)

        def ioreg_val(key: str) -> Optional[str]:
            m = re.search(r'"%s"\s*=\s*("?)([^"\n]+)\1' % re.escape(key), ioreg)
            return m.group(2).strip() if m else None

        uuid = ioreg_val("IOPlatformUUID")
        serial = ioreg_val("IOPlatformSerialNumber")
        self.facts["hw_uuid"] = uuid
        self.add(
            "B10", g, "IOPlatformUUID（硬件 UUID）",
            "客户端本构建未直接读取 [观测]；但系统层恒存在，任何原生模块 / 后续版本都可取",
            "潜在：若有原生模块或未来版本读取 → 机器级唯一值",
            "这是本机最强硬件标识，一旦被读取则重装无效",
            RISK if uuid else INFO, uuid or "(读不到)",
        )
        self.add(
            "B11", g, "IOPlatformSerialNumber（序列号）",
            "客户端未读取 [观测]",
            "潜在：保修/机型识别",
            "序列号可定位到具体机器与购买区域",
            RISK if serial else INFO, serial or "(读不到)",
        )
        self.add(
            "B12", g, "hw.model（机型标识）",
            "os.cpus()[0].model 的补充；部分代码路径用 hw.model",
            "潜在",
            "机型 + 内存 + build 三件套已经很接近唯一",
            INFO, out(["sysctl", "-n", "hw.model"], 5).strip(),
        )

        host = socket.gethostname()
        local_host = out(["scutil", "--get", "LocalHostName"], 5).strip()
        comp_name = out(["scutil", "--get", "ComputerName"], 5).strip()
        self.facts["hostname"] = host
        self.add(
            "B13", g, "hostname → 上行字段 machine_name",
            "index.chunk-CFRZene0.js@132373 machineName: os.hostname()；"
            "index.chunk-BfOAx4v9.js@6049967 registerEnvironment({machine_name})",
            "Cowork 环境注册接口（服务端持久保存）",
            "主机名常含真实姓名/公司/城市，是最容易被忽视的地理线索",
            RISK, {"hostname": host, "LocalHostName": local_host, "ComputerName": comp_name},
            note="这条是明文上传，不是哈希",
        )

        user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        self.add(
            "B14", g, "用户名 / homePath",
            "os.userInfo() + machineName/homePath 同 schema（@1745078）",
            "Cowork 环境注册 + 客户端内部路径",
            "家目录路径含用户名，可反推真实姓名",
            RISK,
            {"USER": user, "HOME": str(HOME)},
        )

        cfg_candidates = [
            user_data_dir() / "claude_desktop_config.json",
            user_data_dir().parent / f"{user_data_dir().name}-3p" / "claude_desktop_config.json",
        ]
        found = []
        for c in cfg_candidates:
            st, desc = path_state(c)
            if st != "absent":
                j = load_json(c)
                found.append({"path": str(c), "state": st, "size": desc,
                              "deploymentMode": (j or {}).get("deploymentMode")
                              if isinstance(j, dict) else None})
        self.add(
            "B15", g, "deploymentMode（claude_desktop_config.json）",
            "index.pre.js w0(): ZQ()=join(UQ(),HQ)，UQ() 在 darwin 上追加 '-3p'",
            "telemetry deployment_mode / config_source + preload argv",
            "决定 userData 是否被改写到 Claude-3p；会影响清理路径",
            INFO if not found else RISK,
            found or "(两处均不存在)",
        )

        self.add(
            "B16", g, "Sentry device context",
            "index.pre.js@259755 R_='Context': W_() → boot_time/arch/memory_size/"
            "free_memory/processor_count/cpu_description/processor_frequency",
            "Sentry 崩溃/错误上报（独立于 telemetry）",
            "CPU 型号 + 频率 + 核数 + 内存 是准唯一硬件组合",
            RISK,
            {
                "processor_count": os.cpu_count(),
                "cpu_description": cpu,
                "memory_size": mem,
                "boot_time": _boot_time(),
            },
        )

    # ---- C 语言 / 区域 / 时区 ----
    def group_c(self) -> None:
        g = "C"

        tz, tzsrc = resolved_timezone()
        self.facts["tz"] = tz
        self.facts["tz_offset"] = utc_offset_hours(tz)
        self.add(
            "C01", g, "解析出的时区（Intl.DateTimeFormat().resolvedOptions().timeZone）",
            "index.chunk-DuQJhuk4.js@676836 / oZ3hATSw.js@298959,379737 / "
            "BfOAx4v9.js@5747741(Jla) / pre.js H_()",
            "<env> 提示词 Timezone 行 + VM bash 的 TZ + Claude Code 子进程 TZ + "
            "CRON_TZ + Sentry culture.timezone",
            "这是最核心的地理信号：客户端把 IANA 时区明文写进每一次模型请求",
            CRIT, {"timezone": tz, "source": tzsrc,
                   "utc_offset_hours": self.facts["tz_offset"]},
        )

        self.add(
            "C02", g, "TZ 环境变量",
            "Node/Electron 的 Intl 会优先读 TZ；客户端自己也往子进程塞 TZ",
            "若设置则覆盖系统时区 → 直送 Intl",
            "设错 TZ 会让时间戳逻辑和时区信号一起错位",
            OK if not os.environ.get("TZ") else RISK,
            os.environ.get("TZ") or "(未设置)",
        )

        link_tgt = ""
        try:
            if os.path.islink("/etc/localtime"):
                link_tgt = os.readlink("/etc/localtime")
        except Exception:  # noqa: BLE001
            pass
        self.add(
            "C03", g, "/etc/localtime 符号链接",
            "系统层时区配置（Intl 的最终来源之一）",
            "决定 C01",
            "只读观测",
            INFO, link_tgt or "(不是符号链接)",
        )

        sset = out(["/usr/sbin/systemsetup", "-gettimezone"], 6).strip()
        self.add(
            "C04", g, "systemsetup -gettimezone",
            "系统层（需 root 才可读/改）",
            "决定 C01",
            "改时区必须走这里，只改 UI 无效",
            INFO, sset or "(需要 root 或不可用)",
        )

        gd = self.cache.setdefault("defaults", global_defaults())
        langs = gd.get("AppleLanguages")
        if isinstance(langs, str):
            langs = [langs]
        langs = langs or []
        self.facts["apple_languages"] = langs
        self.add(
            "C05", g, "AppleLanguages（首选语言顺序）",
            "app.getPreferredSystemLanguages() 在 macOS 上来自这里",
            "preload argv preferredSystemLanguages + renderer desktopPreferredLanguages",
            "语言顺序是文化归属信号；en-US 优先 = 美区设定",
            INFO, langs,
        )

        norm = yur(langs)
        self.facts["normalized_langs"] = norm
        self.add(
            "C06", g, "YUr() 归一化后的实际上行值",
            "index.chunk-BfOAx4v9.js@4140347  function YUr(e)",
            "argv --desktop-managed-config= 里的 preferredSystemLanguages",
            "这才是服务端看到的数组；重复/C/POSIX 会被去掉",
            INFO, norm,
        )

        # C06b: Xgt() —— UI locale 解析。按顺序遍历，命中即停；全落空回退 en-US
        UI_CATALOG = ["de-DE", "en-US", "es-419", "es-ES", "fr-FR", "hi-IN",
                      "id-ID", "it-IT", "ja-JP", "ko-KR", "pt-BR"]   # Bgt 表
        picked, how, src = "en-US", "fallback", None
        for L in norm:
            if L in UI_CATALOG:
                picked, how, src = L, "exact", L
                break
            pre = L.split("-")[0]
            hit = next((k for k in UI_CATALOG if k.startswith(pre + "-")), None)
            if hit:
                picked, how, src = hit, "prefix", L
                break
        backup_used = bool(norm) and src is not None and src != norm[0]
        self.facts["ui_locale"] = picked
        self.add(
            "C06b", g, "Xgt() → UI locale 解析结果（是否动用了备用语言）",
            "index.chunk-BfOAx4v9.js@1707335  Xgt(): 遍历 getPreferredSystemLanguages()，"
            "精确→前缀→回退 qg='en-US'；catalog 表 Bgt 共 11 项",
            "只有这一处按顺序回退；结果被持久化到 <userData>-3p/.../claude_desktop_config.json 的 locale",
            "catalog 里没有 zh-*，所以备份中文即使排第一也匹配不到；但整份数组仍会外传",
            RISK if backup_used else INFO,
            {"preferred": norm, "catalog_size": len(UI_CATALOG),
             "resolved": picked, "match": how, "resolved_from": src,
             "backup_language_used": backup_used,
             "catalog_has_zh": any(x.startswith("zh") for x in UI_CATALOG)},
        )

        apple_locale = gd.get("AppleLocale")
        self.facts["apple_locale"] = apple_locale
        self.add(
            "C07", g, "AppleLocale",
            "app.getSystemLocale() / app.getLocale()",
            "客户端诊断 + 影响 Intl 默认格式",
            "en_US 与 en_GB 的差异会被区域判定利用",
            INFO, apple_locale,
        )

        self.add(
            "C08", g, "getLocale() / getSystemLocale() 近似",
            "index.chunk-BfOAx4v9.js@5204881 诊断串 + Xgt() 语言回退",
            "本地（诊断串会上报 Sentry）",
            "Sentry 上报里带 Locale 明文",
            INFO,
            {"getLocale≈": (langs[0] if langs else None),
             "getSystemLocale=": apple_locale},
        )

        env_loc = {k: os.environ.get(k) for k in
                   ("LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_NUMERIC")}
        nonzero = {k: v for k, v in env_loc.items() if v}
        self.add(
            "C09", g, "POSIX locale 环境变量",
            "进程环境；客户端在调用 ps 时会强制 LC_ALL=C（@1419799）",
            "影响子进程输出解析；本身不上行",
            "如果 GUI 会话里 env 与系统不一致，会出现难查的偏移",
            INFO, nonzero or "(全部未设置)",
        )

        icu_keys = ["AppleICUForce24HourTime", "AppleICUForce12HourTime",
                    "AppleMetricUnits", "AppleMeasurementUnits",
                    "AppleTemperatureUnit", "AppleFirstWeekday", "AppleLocale",
                    "AppleCurrency"]
        icu = {k: gd.get(k) for k in icu_keys if gd.get(k) is not None}
        self.add(
            "C10", g, "ICU / 区域格式偏好",
            "影响 Intl 输出格式（时间、日期、计量、货币）",
            "间接：模型请求里的日期串格式由它决定",
            "12h vs 24h、°F vs °C 是国别强特征",
            INFO, icu or "(未设置，走 locale 默认)",
        )

        self.add(
            "C11", g, "Sentry culture context = {locale, timezone}",
            "index.pre.js@259755  H_() → Intl.DateTimeFormat().resolvedOptions()",
            "Sentry 事件附加 context（与 telemetry 是两条独立管道）",
            "即使 telemetry 被关，Sentry 仍带时区",
            CRIT, {"locale": (norm[0] if norm else apple_locale),
                   "timezone": tz},
            note="宗教信仰之外，这是最容易被忽略的第二条时区泄漏通道",
        )

        self.add(
            "C12", g, "<env> 提示词里注入的 Timezone 行",
            "index.chunk-BfOAx4v9.js@2450854 模板 / DuQJhuk4.js@676836 替换",
            "每次模型请求的 system prompt",
            "模型侧也能看到你的时区；这是明文，不是元数据",
            CRIT,
            {"template":
             "Today's date: {{currentDateTime}} (for more granularity, use bash)\n"
             "Timezone: {{currentTimezone}}\n"
             "Model: {{modelName}}\n"
             "User name: {{accountName}}",
             "rendered_timezone": tz},
        )

        self.add(
            "C13", g, "CRON_TZ 注入（定时任务）",
            "index.chunk-BfOAx4v9.js@5747741  Qla(): `CRON_TZ=${n} ${expr}`",
            "scheduled tasks 的 cron 表达式（服务端可见）",
            "时区被硬编码进 cron 字符串，随任务一起持久化",
            RISK, f"CRON_TZ={tz}",
        )

        kb = out(["defaults", "read", "com.apple.HIToolbox", "AppleSelectedInputSources"], 8)
        self.add(
            "C14", g, "键盘 / 输入法布局",
            "客户端未读取 [观测]",
            "潜在：UI 层可读 navigator.keyboard / 输入源列表",
            "输入法列表能暴露母语与地区（例如中文拼音 + 简体）",
            RISK if kb.strip() else INFO,
            (re.findall(r'"KeyboardLayout Name"\s*=\s*"?([^";]+)', kb)
             or re.findall(r'"Input Mode"\s*=\s*"?([^";]+)', kb)
             or ("(读不到)" if not kb.strip() else kb.strip()[:200])),
        )

        self.add(
            "C15", g, "系统时钟与真实时间偏移",
            "所有请求的时间戳（telemetry timestamp / env currentDateTime）",
            "telemetry + 提示词日期",
            "时钟明显偏移会被当作异常；也会让日期串暴露时区",
            INFO, {"now": datetime.now().isoformat(timespec="seconds"),
                   "utc_now": datetime.now(timezone.utc).isoformat(timespec="seconds")},
        )

    # ---- D 网络出口 ----
    def group_d(self) -> None:
        g = "D"
        if self.args.offline:
            for pid, title in (
                ("D01", "公网 IPv4"), ("D02", "IPv4 地理归属"), ("D03", "地理归属交叉校验"),
                ("D04", "ASN / 运营商"), ("D05", "ASN 类型（数据中心 vs 住宅）"),
                ("D06", "PTR 反解"), ("D07", "公网 IPv6"), ("D18", "IPv4 地址段归属交叉"),
            ):
                self.add(pid, g, title, "网络探针", "服务端边缘可见", "见正文", SKIP, "(offline)")
            self._local_network(g)
            return

        ip4 = ""
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            _c, _h, body = http(url, 6)
            cand = body.strip()
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", cand):
                ip4 = cand
                break
        self.facts["ip4"] = ip4

        geo_a: dict = {}
        geo_b: dict = {}
        if ip4:
            ja = http_json(f"https://ipinfo.io/{ip4}/json", 8) or {}
            if isinstance(ja, dict):
                geo_a = ja
            jb = http_json(f"https://ipapi.co/{ip4}/json/", 8) or {}
            if isinstance(jb, dict):
                geo_b = jb
        self.facts["geo_a"] = geo_a
        self.facts["geo_b"] = geo_b

        self.add(
            "D01", g, "公网 IPv4",
            "服务端边缘（Cloudflare）第一层判定，客户端不读但服务器必看",
            "边缘 → 区域策略",
            "这一层失败时，客户端只会看到 Cloudflare 页面或 INVALID_RECAPTCHA",
            INFO if ip4 else SKIP, ip4 or "(取不到)",
        )

        self.add(
            "D02", g, "IPv4 地理归属（ipinfo）",
            "服务端侧数据，客户端不可见",
            "区域判定",
            "城市/时区/国家三项都会被拿去和你的 C01/C07 对比",
            INFO if geo_a else SKIP,
            {k: geo_a.get(k) for k in ("city", "region", "country", "loc", "timezone", "org")
             if geo_a.get(k)} or "(无数据)",
        )

        self.add(
            "D03", g, "地理归属交叉校验（ipapi）",
            "第二家数据库；两家不一致本身就是风险信号",
            "区域判定",
            "库间分歧（例如 LACNIC 段在 LA 宣告）容易触发人工复核",
            INFO if geo_b else SKIP,
            {k: geo_b.get(k) for k in
             ("city", "region", "country_code", "country_name", "timezone", "org", "asn")
             if geo_b.get(k)} or "(无数据)",
        )

        org = (geo_a.get("org") or geo_b.get("org") or "") if (geo_a or geo_b) else ""
        asn = (geo_b.get("asn") or "") if geo_b else ""
        self.facts["asn_org"] = org
        self.add(
            "D04", g, "ASN / 运营商",
            "服务端侧",
            "区域 + 反滥用判定",
            "ASN 是判断「住宅 vs 机房」的关键；VPN 出口通常落在机房 ASN",
            INFO, {"org": org, "asn": asn} if org else "(无数据)",
        )

        is_dc, dc_name = classify_asn(org, str(geo_b.get("org", "")) if geo_b else "")
        self.facts["is_datacenter"] = is_dc
        self.facts["dc_name"] = dc_name
        self.add(
            "D05", g, "ASN 类型判定（数据中心 vs 住宅）",
            "启发式：按 org 关键词匹配（脚本逻辑，非客户端代码）",
            "区域 / 反滥用判定",
            "机房 IP 是「VPN 被识别」的最常见原因；住宅 IP 才能通过这一层",
            CRIT if is_dc else (OK if org else SKIP),
            {"is_datacenter": is_dc, "matched": dc_name or None, "org": org},
            note="关键词表见脚本 DC_PATTERNS",
        )

        ptr = ""
        if ip4:
            try:
                ptr = socket.gethostbyaddr(ip4)[0]
            except Exception:  # noqa: BLE001
                s = out(["dig", "+short", "-x", ip4], 6).strip()
                ptr = s or ""
        self.facts["ptr"] = ptr
        leak = bool(ptr) and bool(re.search(
            r"(?i)(host|vps|server|cloud|dmit|colo|dedicated|static|ip-|-ip)", ptr))
        self.add(
            "D06", g, "PTR 反解",
            "服务端侧",
            "反滥用 / 人工复核",
            "PTR 直接写着托管商域名时，等于自报「我在机房」",
            CRIT if leak else (INFO if ptr else OK),
            ptr or "(无 PTR)",
        )

        ip6 = ""
        for url in ("https://api64.ipify.org", "https://v6.ident.me"):
            _c, _h, body = http(url, 6)
            cand = body.strip()
            if ":" in cand and re.fullmatch(r"[0-9a-fA-F:]+", cand):
                ip6 = cand
                break
        self.facts["ip6"] = ip6
        self.add(
            "D07", g, "公网 IPv6",
            "服务端侧",
            "区域判定（若启用 AAAA）",
            "IPv6 常绕过只配了 IPv4 的代理，直接暴露真实位置 —— 高危泄漏点",
            CRIT if ip6 else OK, ip6 or "(无 IPv6 出口)",
        )

        self._local_network(g)

        self.add(
            "D15", g, "代理环境变量",
            "客户端不读；但 Chromium/Electron 网络栈会读",
            "实际出口选择",
            "代理变量与实际出口不一致会造成时区/语言/出口三者矛盾",
            INFO,
            {k: v for k, v in os.environ.items()
             if k.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                              "http_proxy", "https_proxy", "all_proxy", "no_proxy")}
            or "(未设置)",
        )

        sc_proxy = out(["scutil", "--proxy"], 8)
        self.add(
            "D16", g, "系统代理设置（scutil --proxy）",
            "Electron 默认跟随系统代理",
            "实际出口选择",
            "PAC/自动代理可能把部分流量走直连 → IPv6 或 DNS 泄漏",
            INFO, sc_proxy.strip()[:600] or "(无输出)",
        )

        if self.args.anthropic:
            code, hdrs, body = http("https://api.anthropic.com/api/hello", 8)
            interesting = {k: v for k, v in hdrs.items()
                           if k.lower() in ("cf-ray", "cf-mitigated", "cf-cache-status",
                                            "server", "x-envoy-upstream-service-time",
                                            "content-type", "retry-after")}
            blocked = (code in (403, 429, 451)
                       or hdrs.get("cf-mitigated", "").lower() in ("challenge", "block"))
            self.add(
                "D17", g, "边缘探测 https://api.anthropic.com/api/hello",
                "CLI preflight: [`${BASE_API_URL}/api/hello`, `${TOKEN_URL.origin}/v1/oauth/hello`]",
                "边缘层决策（Cloudflare）",
                "这一层决定你是否连登录页都看不到；403/451/challenge 就是被边缘拦",
                CRIT if blocked else (INFO if code else SKIP),
                {"status": code, "headers": interesting,
                 "body_head": (body or "")[:200]},
                note="未认证公开端点，与客户端 preflight 同一目标",
            )
        else:
            self.add(
                "D17", g, "边缘探测 https://api.anthropic.com/api/hello",
                "CLI preflight", "边缘层决策", "被边缘拦截", SKIP, "(--no-anthropic)",
            )

        # D18 地址段归属交叉
        if ip4:
            first = ".".join(ip4.split(".")[:2])
            self.add(
                "D18", g, "IPv4 地址段 / RIR 归属交叉",
                "服务端侧数据（RIR 分配 vs BGP 宣告）",
                "区域 / 人工复核",
                "LACNIC 段在北美宣告、或 RIR 国家与 geo 国家不符，是典型「代理」特征",
                RISK,
                {"prefix_16": f"{first}.0.0/16",
                 "geo_country": geo_a.get("country") or geo_b.get("country_code"),
                 "note": "RIR 归属需外部 whois，脚本不发起（避免额外指纹）"},
            )

    def _local_network(self, g: str) -> None:
        # 路由 / DNS
        route = out(["route", "-n", "get", "default"], 8)
        iface = re.search(r"interface:\s*(\S+)", route)
        gw = re.search(r"gateway:\s*(\S+)", route)
        self.add(
            "D08", g, "默认路由（接口 + 网关）",
            "系统层；客户端不读 [观测]",
            "潜在：网络环境指纹",
            "网关段能定位到局域网/ISP 层级",
            INFO, {"interface": iface.group(1) if iface else None,
                   "gateway": gw.group(1) if gw else None},
        )

        dns = out(["scutil", "--dns"], 8)
        resolvers = list(dict.fromkeys(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", dns)))
        self.facts["dns"] = resolvers
        self.add(
            "D09", g, "DNS 解析器",
            "客户端不读 [观测]",
            "潜在：DNS 泄漏检测",
            "DNS 走本地 ISP 而 HTTP 走代理 = 经典泄漏，服务端与 CDN 都能看到解析来源",
            RISK if resolvers else INFO, resolvers or "(无输出)",
        )

        # 四个 VPN 探针
        ifaces = probe_vpn_ifaces()
        self.facts["vpn_ifaces"] = ifaces
        self.add(
            "D10", g, "VPN 探针①：utun/ppp/ipsec/tun 接口",
            "index.chunk-BfOAx4v9.js I2r(): /sbin/ifconfig + /^(utun\\d+|ppp\\d+|ipsec\\d+|tun\\d+):/gm",
            "仅进 diagnostics（不单独上行）",
            "注意：macOS 基线本身就有 utun0-3，命中共不代表在用 VPN",
            INFO, ifaces or "(无)",
        )

        connected = probe_scutil_connected()
        self.facts["vpn_connected"] = connected
        self.add(
            "D11", g, "VPN 探针②：scutil --nc list（唯一决定 vpnActive 的输入）",
            "index.chunk-BfOAx4v9.js L2r() + V2r(): vpnActive = connectedVPNs.length > 0",
            "lam_vm_startup_failed 事件（仅在 VM 启动失败时）",
            "这是 vpnActive 布尔值的唯一来源；系统 VPN 未连接则为 false",
            OK if not connected else CRIT, connected or "(无已连接的系统 VPN 服务)",
        )

        bootpd = probe_bootpd()
        self.facts["bootpd"] = bootpd
        self.add(
            "D12", g, "VPN 探针③：bootpd 进程（Internet 共享）",
            "index.chunk-BfOAx4v9.js R2r(): pgrep -x bootpd",
            "仅进 diagnostics",
            "Internet 共享开启会被当作可疑网络环境",
            RISK if bootpd else OK, "running" if bootpd else "not running",
        )

        bridges = probe_bridge_vmnet()
        self.facts["bridges"] = bridges
        self.add(
            "D13", g, "VPN 探针④：bridge/vmnet 接口",
            "index.chunk-BfOAx4v9.js z2r(): ifconfig -a + /^(bridge\\d+|vmnet\\d+):/gm",
            "仅进 diagnostics",
            "虚拟机/容器网络会命中 bridge0，属 macOS 常见基线",
            INFO, bridges or "(无)",
        )

        vpn_active = len(connected) > 0
        self.facts["vpn_active"] = vpn_active
        self.add(
            "D14", g, "V2r() 聚合判定 vpnActive",
            "index.chunk-BfOAx4v9.js V2r() → {vpnActive, vpnInterfaces, connectedVPNs, "
            "bootpdRunning, bridgeInterfaces, error}",
            "只用于 lam_vm_startup_failed 的用户提示文案",
            "关键结论：vpnActive 只看 connectedVPNs；utun 命中不影响它",
            OK if not vpn_active else CRIT,
            {"vpnActive": vpn_active, "vpnInterfaces": ifaces,
             "connectedVPNs": connected, "bootpdRunning": bootpd,
             "bridgeInterfaces": bridges},
            note="这些探针不在常规埋点里跑，只在 Cowork VM 启动失败路径触发",
        )

    # ---- E 本地残留 ----
    def group_e(self) -> None:
        g = "E"

        cands: list[tuple[str, Path]] = [
            ("darwin/appData", HOME / "Library" / "Application Support" / "Claude"),
            ("darwin/appData", HOME / "Library" / "Application Support" / "Claude-3p"),
            ("darwin/logsParent", HOME / "Library" / "Logs" / "Claude"),
            ("darwin/logsParent", HOME / "Library" / "Logs" / "Claude-3p"),
        ]
        rows = []
        for label, p in cands:
            st, desc = path_state(p)
            rows.append({"role": label, "path": str(p), "state": st, "detail": desc})
        live = [r for r in rows if r["state"] != "absent"]
        self.add(
            "E01", g, "userData 候选表（oHe）",
            "index.chunk-BfOAx4v9.js oHe @862179  darwin:[appData×2, logsParent×2]",
            "磁盘",
            "这些目录里含 ant-did / config.json / window-state.json / update-attempt",
            RISK if live else OK, rows,
        )

        # 兄弟目录扫描
        app_support = HOME / "Library" / "Application Support"
        siblings = []
        try:
            for entry in sorted(os.listdir(app_support)):
                if entry.startswith("Claude"):
                    p = app_support / entry
                    st, desc = path_state(p)
                    siblings.append({"name": entry, "state": st, "detail": desc})
        except Exception:  # noqa: BLE001
            pass
        self.add(
            "E02", g, "兄弟目录扫描（会被当作可导入账号）",
            "index.chunk-CxzPVbs5.js@5449 re(): if(!i.startsWith('Claude')) continue; "
            "→ 命中即 emit origin:'sibling-3p'",
            "sibling-import.json / 客户端提示「发现另一个 Claude 账号」",
            "任何 Claude* 目录都会被 offer 导入，等于把旧账号带进新账号",
            RISK if siblings else OK, siblings or "(无 Claude* 目录)",
        )

        shipit = HOME / "Library" / "Caches" / "com.anthropic.claudefordesktop.ShipIt"
        st, desc = path_state(shipit)
        files = []
        if st == "dir":
            try:
                for f in sorted(shipit.iterdir()):
                    files.append(f.name)
            except Exception:  # noqa: BLE001
                pass
        self.add(
            "E03", g, "ShipIt 更新器缓存",
            "index.chunk-BfOAx4v9.js wti() @4461535: "
            "join(home,'Library','Caches','com.anthropic.claudefordesktop.ShipIt')",
            "磁盘；其 stderr 尾部会上传为 shipit_stderr_tail",
            "不含身份，但残留说明这台机器装过；且失败日志会随 telemetry 上传",
            RISK if st != "absent" else OK,
            {"path": str(shipit), "state": st, "detail": desc, "entries": files[:20]},
        )

        # Keychain 服务名清单
        if self.args.keychain and IS_MAC:
            claude_services = [
                "Claude Code-device-keys", "Claude Code", "Claude Code-credentials",
                "com.anthropic.claudefordesktop", "Claude", "anthropic",
            ]

            def kc_lookup(svc: str):
                rc, stdout, _ = sh(["security", "find-generic-password", "-s", svc], 6)
                if rc != 0:
                    return None
                acct = re.search(r'"acct"<blob>="([^"]*)"', stdout)
                mdat = re.search(r'"mdat"<timedate>=0x([0-9A-Fa-f]+)', stdout)
                return {"service": svc,
                        "account": acct.group(1) if acct else None,
                        "modified": _apple_time(mdat.group(1)) if mdat else None}

            hits = [h for h in (kc_lookup(x) for x in claude_services) if h]
            self.cache["keychain_claude_hits"] = hits
            self.add(
                "E04", g, "Keychain 中的 Claude 专属条目",
                "CLI: lke()=`Claude Code${suffix}${e}${i}` (+ '-credentials')",
                "磁盘（Keychain）",
                "设备私钥与 OAuth 凭据都在这；删账号不删 Keychain = 设备仍被认",
                CRIT if hits else OK, hits or "(无命中)",
            )
            chrome = kc_lookup("Chrome Safe Storage")
            self.add(
                "E04b", g, "Keychain 条目「Chrome Safe Storage」（Chrome，不是 Claude）",
                "index.chunk-DbZjmJ_X.js: [ChromeImport] claude-safe keychain binding unavailable",
                "客户端用它解密 Chrome cookie 做账号导入",
                "存在只说明装了 Chrome；但客户端因此具备「从 Chrome 读 cookie」的能力",
                INFO, chrome or "(不存在)",
            )
        else:
            self.add(
                "E04", g, "Keychain 中的 Claude 相关条目",
                "CLI 凭据命名", "磁盘（Keychain）", "设备仍被认",
                SKIP, "(跳过)",
            )

        # Preferences / Caches / HTTPStorages / Containers
        glob_targets = [
            ("E05", "~/Library/Preferences/com.anthropic.*",
             str(HOME / "Library" / "Preferences") + "/com.anthropic.*"),
            ("E06", "~/Library/Caches/*Claude*",
             str(HOME / "Library" / "Caches") + "/*Claude*"),
            ("E07", "~/Library/HTTPStorages/*claude*",
             str(HOME / "Library" / "HTTPStorages") + "/*claude*"),
            ("E08", "~/Library/Containers / Group Containers",
             None),
            ("E09", "~/Library/Saved Application State / WebKit",
             None),
            ("E10", "Cookies（binarycookies）",
             str(HOME / "Library" / "Cookies") + "/*claude*"),
        ]
        import glob as _glob
        for pid, title, pattern in glob_targets:
            if pattern:
                matches = sorted(_glob.glob(pattern))
            elif pid == "E08":
                matches = sorted(_glob.glob(str(HOME / "Library" / "Containers") + "/*laude*")) + \
                          sorted(_glob.glob(str(HOME / "Library" / "Group Containers") + "/*laude*"))
            else:
                matches = sorted(_glob.glob(str(HOME / "Library" / "Saved Application State") +
                                            "/*laude*")) + \
                          sorted(_glob.glob(str(HOME / "Library" / "WebKit") + "/*laude*"))
            rows = []
            for m in matches:
                st, desc = path_state(Path(m))
                rows.append({"path": m, "state": st, "detail": desc})
            self.add(
                pid, g, title,
                "标准 macOS 应用残留位置（客户端不主动写，但系统会写）",
                "磁盘",
                "说明该机器运行过该应用；cookies 会让网页端保持登录态",
                RISK if rows else OK, rows or "(无)",
            )

        app = Path("/Applications/Claude.app")
        st, desc = path_state(app)
        self.add(
            "E11", g, "/Applications/Claude.app",
            "安装位置",
            "磁盘",
            "存在即说明装过；卸载后 info.plist / quarantine 记录仍可能留存",
            RISK if st != "absent" else OK, f"{app} → {st} ({desc})",
        )

        qdb = HOME / "Library" / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"
        q = out(["sqlite3", str(qdb),
                 "select count(*) from LSQuarantineEvent where "
                 "LSQuarantineDataURLString like '%laude%';"], 8).strip()
        if not q:
            st_q, desc_q = path_state(qdb)
            q = "" if st_q == "absent" else f"db={st_q}({desc_q}) 无 sqlite3 可读"
        self.add(
            "E12", g, "Gatekeeper 隔离记录（LSQuarantine）",
            "系统层",
            "磁盘（系统数据库）",
            "记录你从哪个 URL 下载过 Claude —— 可反推下载渠道与时间",
            RISK if (q.strip() and q.strip() != "0") else INFO,
            q.strip() or "(读不到或无记录)",
        )

        cfg_lib = HOME / "Library" / "Application Support" / "Claude-3p" / "configLibrary"
        st, desc = path_state(cfg_lib)
        self.add(
            "E13", g, "configLibrary 目录",
            "index.chunk-BfOAx4v9.js $Ve()/e$/t$: join(UQ(),'configLibrary')",
            "磁盘（配置库，含 _meta.json）",
            "第三方/多部署模式下的配置缓存，常规清理常漏",
            RISK if st != "absent" else OK, f"{cfg_lib} → {st} ({desc})",
        )

        loc = out(["ls", "-la", str(HOME / "Library" / "Application Support")], 10)
        self.add(
            "E14", g, "Application Support 顶层快照",
            "总览（便于人工核对）",
            "磁盘",
            "一行一条，看有没有被前面漏掉的 Claude 相关项",
            INFO, [l for l in loc.splitlines() if "laude" in l or "nthropic" in l] or "(无)",
        )

    # ---- F CLI ----
    def group_f(self) -> None:
        g = "F"

        cj = HOME / ".claude.json"
        st, desc = path_state(cj)
        self.add(
            "F01", g, "~/.claude.json",
            "CLI 全局配置（708 处 projects 引用）",
            "本地 + 部分上行",
            "文件在 = CLI 用过；里面的 userID/machineID 是重装也要清的东西",
            RISK if st != "absent" else OK, f"{cj} → {st} ({desc})",
        )

        cdir = HOME / ".claude"
        st, desc = path_state(cdir)
        sub: list[str] = []
        if st == "dir":
            try:
                sub = sorted(x.name for x in cdir.iterdir())[:40]
            except Exception:  # noqa: BLE001
                pass
        self.add(
            "F02", g, "~/.claude/ 目录树",
            "CLI 状态目录",
            "本地",
            "可能含 .device-keys / projects / statsig / todos 等",
            RISK if st != "absent" else OK,
            {"path": str(cdir), "state": st, "detail": desc, "entries": sub},
        )

        envs = {k: v for k, v in os.environ.items()
                if k.startswith("CLAUDE_") or k.startswith("ANTHROPIC_")}
        self.add(
            "F03", g, "CLAUDE_* / ANTHROPIC_* 环境变量",
            "CLI: CLAUDE_CONFIG_DIR / CLAUDE_SECURESTORAGE_CONFIG_DIR / "
            "CLAUDE_USER_DATA_DIR / ANTHROPIC_*",
            "决定配置路径与 API 目标",
            "这些变量会把配置写到非默认位置，或把请求改到自建网关",
            RISK if envs else OK, envs or "(未设置)",
        )

        found_bins = []
        for c in ("claude",):
            w = out(["/usr/bin/which", c], 5).strip()
            if w:
                v = out([w, "--version"], 10).strip()
                found_bins.append({"path": w, "version": v})
        for p in (HOME / ".local" / "bin" / "claude",
                  HOME / ".bun" / "bin" / "claude",
                  Path("/opt/homebrew/bin/claude"),
                  Path("/usr/local/bin/claude")):
            if p.exists() and not any(f["path"] == str(p) for f in found_bins):
                v = out([str(p), "--version"], 10).strip()
                found_bins.append({"path": str(p), "version": v})
        self.add(
            "F04", g, "CLI 二进制位置与版本",
            "CLI 单文件 Bun 二进制",
            "本地",
            "版本决定它上报哪些字段",
            INFO if found_bins else SKIP, found_bins or "(未安装)",
        )

        proj = {}
        data = self.cache.get("claude_json")
        if isinstance(data, dict):
            projects = data.get("projects")
            if isinstance(projects, dict):
                proj = {"count": len(projects),
                        "sample": list(projects)[:10]}
        self.add(
            "F05", g, "~/.claude.json → projects（路径历史）",
            "CLI: projects 708 处引用；githubRepoPaths 8 处",
            "本地；githubRepoPaths 可能上行",
            "项目路径含真实姓名/客户名/城市目录名，是最常见的地理泄漏",
            RISK if proj else OK, proj or "(无)",
        )

        git_name = out(["git", "config", "--global", "user.name"], 6).strip()
        git_mail = out(["git", "config", "--global", "user.email"], 6).strip()
        self.add(
            "F06", g, "git 全局身份",
            "CLI 会读 gh / git 凭据（gh auth token, GH_TOKEN）",
            "潜在：随代码/PR 上行",
            "邮箱域名与姓名可反推公司/地区",
            RISK if (git_name or git_mail) else OK,
            {"user.name": git_name or None, "user.email": git_mail or None},
        )

        rc_files = [HOME / ".zshrc", HOME / ".zprofile", HOME / ".bash_profile",
                    HOME / ".bashrc", HOME / ".profile", HOME / ".config" / "fish" / "config.fish"]
        hits = {}
        for f in rc_files:
            t = read_text(f, 500_000)
            if not t:
                continue
            found = [l.strip() for l in t.splitlines()
                     if re.search(r"\b(CLAUDE_|ANTHROPIC_|claude\b)", l)
                     and not l.strip().startswith("#")]
            if found:
                hits[str(f)] = found[:8]
        self.add(
            "F07", g, "shell rc 中的 Claude/Anthropic 配置",
            "进程环境来源",
            "影响 CLI 行为",
            "常见于把 API base 指到第三方网关（会改变服务端看到的来源）",
            RISK if hits else OK, hits or "(无)",
        )

        npm_ls = out(["npm", "ls", "-g", "--depth=0"], 20)
        pkgs = [l.strip() for l in npm_ls.splitlines()
                if "claude" in l.lower() or "anthropic" in l.lower()]
        self.add(
            "F08", g, "全局 npm/bun 包",
            "CLI 分发渠道（installMethod）",
            "本地",
            "installMethod 会随 telemetry 上行",
            INFO, pkgs or "(无相关全局包)",
        )

    # ---- G 一致性 ----
    def group_g(self) -> None:
        g = "G"
        tz = self.facts.get("tz")
        tz_off = self.facts.get("tz_offset")
        geo_a = self.facts.get("geo_a") or {}
        geo_b = self.facts.get("geo_b") or {}
        ip_tz = geo_a.get("timezone") or geo_b.get("timezone")
        ip_country = geo_a.get("country") or geo_b.get("country_code")

        # C 轴降级：时区与出口 IP 一致时，时区通道「存在」但「不矛盾」→ CRIT 降为 RISK
        if tz and ip_tz and tz == ip_tz and not self.args.offline:
            for q in self.results:
                if q.pid in ("C01", "C11", "C12") and q.status == CRIT:
                    q.status = RISK
                    q.note = (q.note + " " if q.note else "") + \
                        "（时区与出口 IP 一致 → 降级为「通道存在」，不计矛盾）"

        # G01 时区 vs IP 时区
        if tz and ip_tz and not self.args.offline:
            ip_off = utc_offset_hours(ip_tz)
            delta = None
            if tz_off is not None and ip_off is not None:
                delta = abs(tz_off - ip_off)
            same = (tz == ip_tz)
            self.facts["tz_vs_ip"] = {"system": tz, "ip": ip_tz, "delta_hours": delta}
            self.add(
                "G01", g, "系统时区 vs 出口 IP 时区",
                "C01（客户端上报）对比 D02（服务端可见）",
                "两者会在同一请求里被并列看到",
                "不一致 = 直接可判定的矛盾；这是最容易被自动化规则抓的一条",
                OK if same else CRIT,
                {"system_timezone": tz, "ip_timezone": ip_tz,
                 "utc_offset_delta_hours": delta},
                weight=0,
            )
        else:
            self.add(
                "G01", g, "系统时区 vs 出口 IP 时区",
                "C01 vs D02", "同一请求内并列", "矛盾判定",
                SKIP, "(offline 或缺数据)",
            )

        # G02 语言/区域 vs IP 国家
        langs = self.facts.get("normalized_langs") or []
        locale = self.facts.get("apple_locale") or ""
        region_from_locale = None
        if isinstance(locale, str) and "_" in locale:
            region_from_locale = locale.split("_")[-1].upper()
        elif isinstance(locale, str) and "-" in locale:
            region_from_locale = locale.split("-")[-1].upper()
        if ip_country and not self.args.offline:
            match = (region_from_locale == ip_country.upper()) if region_from_locale else None
            self.add(
                "G02", g, "系统区域 vs 出口 IP 国家",
                "C05/C07 对比 D02/D03",
                "服务端并列可见",
                "en_US + 美国 IP 一致；zh_CN + 美国 IP 就需要解释",
                OK if match else (RISK if match is False else INFO),
                {"apple_locale": locale, "region_from_locale": region_from_locale,
                 "languages": langs, "ip_country": ip_country,
                 "match": match},
                weight=0,
            )
        else:
            self.add(
                "G02", g, "系统区域 vs 出口 IP 国家",
                "C05/C07 vs D02", "服务端并列可见", "矛盾判定",
                SKIP, "(offline 或缺数据)",
            )

        # G03 ASN
        is_dc = self.facts.get("is_datacenter")
        if not self.args.offline:
            self.add(
                "G03", g, "出口 ASN 类型",
                "D04/D05",
                "服务端区域 / 反滥用",
                "机房 ASN 是被识别为 VPN 的首要原因；住宅 IP 是唯一根治",
                CRIT if is_dc else (OK if self.facts.get("asn_org") else SKIP),
                {"datacenter": is_dc, "matched": self.facts.get("dc_name"),
                 "org": self.facts.get("asn_org")},
                weight=0,
            )

        # G04 PTR
        ptr = self.facts.get("ptr")
        if not self.args.offline:
            self.add(
                "G04", g, "PTR 泄漏托管商",
                "D06",
                "服务端 / 人工复核",
                "PTR 里出现 host-by/vps/cloud 等字样等于自报机房",
                RISK if ptr else OK, ptr or "(无 PTR)",
                weight=0,
            )

        # G05 跨账号关联锚点：区分「可以清掉」和「清不掉」的
        clearable: list[str] = []
        inherent: list[str] = []
        data = self.cache.get("claude_json")
        if isinstance(data, dict):
            if data.get("userID"):
                clearable.append("~/.claude.json userID")
            if data.get("machineID"):
                clearable.append("~/.claude.json machineID")
            if data.get("oauthAccount"):
                clearable.append("~/.claude.json oauthAccount")
            if data.get("projects"):
                clearable.append("~/.claude.json projects / githubRepoPaths")
        ud = Path(self.facts.get("user_data") or "")
        if str(ud) and (ud / "ant-did").exists():
            clearable.append("ant-did（桌面端设备 ID）")
        if (HOME / ".claude" / ".device-keys").exists():
            clearable.append("~/.claude/.device-keys（设备私钥）")
        if self.cache.get("keychain_claude_hits"):
            clearable.append("Keychain 中的 Claude 条目")

        if self.facts.get("hw_uuid"):
            inherent.append(f"IOPlatformUUID={self.facts['hw_uuid']}")
        if self.facts.get("cpu_model"):
            inherent.append(f"cpu_model={self.facts['cpu_model']}")
        if self.facts.get("hostname"):
            inherent.append(f"hostname={self.facts['hostname']}（machine_name 上行）")
        if self.facts.get("normalized_langs"):
            inherent.append(f"preferredSystemLanguages={self.facts['normalized_langs']}")
        if self.facts.get("tz"):
            inherent.append(f"timezone={self.facts['tz']}（每次请求）")

        self.add(
            "G05", g, "跨账号关联锚点：可清理 vs 固有",
            "综合 A/B/C/E/F",
            "服务端可用来把新账号关联到旧账号",
            "clearable 全部清掉才不会带过去；inherent 清不掉，是否被用 [不可判定]",
            CRIT if clearable else (RISK if inherent else OK),
            {"clearable": clearable or "(无，已清干净)",
             "inherent": inherent or "(无)"},
            weight=0,
        )

    # ---- 评分 ----
    def score(self) -> dict:
        n = {k: 0 for k in (CRIT, RISK, INFO, OK, SKIP)}
        for p in self.results:
            n[p.status] = n.get(p.status, 0) + 1
        raw = sum(p.weight if p.weight is not None else STATUS_WEIGHT.get(p.status, 0)
                  for p in self.results)
        return {"counts": n, "raw_weight": raw,
                "exposure_score": min(100, raw)}


def user_data_dir() -> Path:
    env = os.environ.get("CLAUDE_USER_DATA_DIR")
    if env:
        return Path(env)
    return HOME / "Library" / "Application Support" / "Claude"


def _boot_time() -> Optional[str]:
    if IS_MAC:
        s = out(["sysctl", "-n", "kern.boottime"], 5)
        m = re.search(r"sec\s*=\s*(\d+)", s)
        if m:
            from datetime import datetime as _dt
            return _dt.fromtimestamp(int(m.group(1))).isoformat(timespec="seconds")
    return None


def _apple_time(hexstr: str) -> Optional[str]:
    """Apple CFAbsoluteTime (2001-01-01 起算的秒) → ISO"""
    try:
        from datetime import datetime as _dt, timedelta as _td
        secs = int(hexstr, 16)
        return (_dt(2001, 1, 1) + _td(seconds=secs)).isoformat(timespec="seconds")
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------

def _emit(label: str, text: object, pad: str = "    ") -> None:
    lines = str(text).splitlines() or [""]
    print(f"{pad}{label}  {lines[0]}")
    for ln in lines[1:]:
        print(f"{pad}{' ' * len(label)}  {ln}")


def _val_str(v: object) -> str:
    if v is None:
        return "(none)"
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, indent=2)
    return str(v)


def render_console(b: Bench, compact: bool = False) -> None:
    W = 100
    sc = b.score()

    print()
    print("=" * W)
    print(" Claude Desktop / CLI —— macOS 位置探测 Benchmark")
    print(f" {datetime.now().isoformat(timespec='seconds')}"
          f"   host={socket.gethostname()}   platform={sys.platform}"
          f"   probes={len(b.results)}")
    print("=" * W)

    if compact:
        cur = None
        for q in sorted(b.results, key=lambda x: (x.group, x.pid)):
            if q.group != cur:
                cur = q.group
                print()
                print(f"── {cur}. {GROUP_TITLE.get(cur, '')}")
            mark = {CRIT: "!!", RISK: " !", INFO: "  ", OK: "ok", SKIP: "--"}[q.status]
            v = q.value if isinstance(q.value, str) else json.dumps(q.value, ensure_ascii=False)
            print(f" [{mark}] {q.pid} {q.title[:56]:<56} {v[:120]}")
    else:
        cur = None
        for q in sorted(b.results, key=lambda x: (x.group, x.pid)):
            if q.group != cur:
                cur = q.group
                rows = [x for x in b.results if x.group == cur]
                c = sum(1 for x in rows if x.status == CRIT)
                r = sum(1 for x in rows if x.status == RISK)
                tail = f"{len(rows)} 项"
                if c:
                    tail += f"  CRIT={c}"
                if r:
                    tail += f"  RISK={r}"
                print()
                print("─" * W)
                print(f"  {cur}. {GROUP_TITLE.get(cur, '')}   （{tail}）")
                print("─" * W)
            print()
            print(f"{q.pid}  {q.title}   [{q.status}]")
            _emit("读数", _val_str(q.value))
            _emit("代码", q.source)
            _emit("去向", q.channel)
            _emit("风险", q.risk)
            if q.note:
                _emit("备注", q.note)
            if q.weight == 0:
                _emit("计分", "汇总项，不重复计分")

    # ---- 关键事实 / 一致性 ----
    f = b.facts
    print()
    print("=" * W)
    print(" 关键事实与一致性判定")
    print("=" * W)

    tzv = f.get("tz_vs_ip") or {}
    print()
    print(" [时间]")
    print(f"  系统时区        {f.get('tz')}   (UTC{f.get('tz_offset'):+g})"
          if isinstance(f.get("tz_offset"), (int, float))
          else f"  系统时区        {f.get('tz')}")
    print(f"  出口 IP 时区    {tzv.get('ip', '—')}")
    if tzv:
        print(f"  判定            "
              + ("一致" if tzv.get("system") == tzv.get("ip") else "**不一致**"))
    print(f"  语言顺序        {f.get('normalized_langs')}")
    print(f"  系统区域        {f.get('apple_locale')}")
    print(f"  UI locale       {f.get('ui_locale')}")

    print()
    print(" [网络]")
    print(f"  公网 IPv4       {f.get('ip4') or '—'}")
    print(f"  公网 IPv6       {f.get('ip6') or '—'}")
    print(f"  ASN / org       {f.get('asn_org') or '—'}")
    print(f"  数据中心判定    {f.get('is_datacenter')}"
          + (f"   (matched: {f.get('dc_name')})" if f.get("dc_name") else ""))
    print(f"  PTR             {f.get('ptr') or '—'}")
    print(f"  DNS 解析器      {f.get('dns') or '—'}")
    print()
    print(" [客户端 VPN 四个探针 + 聚合]")
    print(f"  utun/ppp 接口   {f.get('vpn_ifaces') or '—'}")
    print(f"  scutil 已连接   {f.get('vpn_connected') or '—'}")
    print(f"  bootpd          {f.get('bootpd')}")
    print(f"  bridge/vmnet    {f.get('bridges') or '—'}")
    print(f"  => vpnActive    {f.get('vpn_active')}")

    print()
    print(" [机器]")
    print(f"  cpu_model       {f.get('cpu_model') or '—'}")
    mem = f.get("total_mem")
    print(f"  内存            {round(mem / 1024 ** 3)} GB" if mem else "  内存            —")
    print(f"  device_class    {f.get('device_class')}")
    print(f"  IOPlatformUUID  {f.get('hw_uuid') or '—'}")
    print(f"  hostname        {f.get('hostname') or '—'}")

    # ---- 汇总 ----
    print()
    print("=" * W)
    print(" 汇总")
    print("=" * W)
    for status, label in ((CRIT, "CRIT  明确矛盾 / 强标识"),
                          (RISK, "RISK  可被定位或跨账号关联")):
        rows = [q for q in b.results if q.status == status]
        print()
        print(f" {label}  —— {len(rows)} 项")
        for q in sorted(rows, key=lambda x: x.pid):
            print(f"   {q.pid}  {q.title}")
    print()
    print(f" CRIT={sc['counts'][CRIT]}  RISK={sc['counts'][RISK]}  "
          f"INFO={sc['counts'][INFO]}  OK={sc['counts'][OK]}  SKIP={sc['counts'][SKIP]}")
    print(f" 位置指纹暴露分（0-100，越高越暴露）: {sc['exposure_score']}")
    print("=" * W)


def render_markdown(b: Bench, path: Path) -> None:
    sc = b.score()
    L: list[str] = []
    A = L.append

    A("# Claude Desktop / CLI —— macOS 位置与身份探测 Benchmark")
    A("")
    A(f"- 生成时间：`{datetime.now().isoformat(timespec='seconds')}`")
    A(f"- 主机：`{socket.gethostname()}` / `{sys.platform}` / `{out(['uname','-m'],5).strip()}`")
    A(f"- 脚本：`tools/claude_location_benchmark.py`（只读，不修改任何系统状态）")
    A(f"- 网络探针：{'已关闭（--offline）' if b.args.offline else '已开启'}"
      f"；`/api/hello`：{'已关闭' if not b.args.anthropic else '已开启'}")
    A("")
    A("**标记约定**：`[观测]` 直接读自代码/二进制/本机命令；`[推断]` 基于观测的合理外推；"
      "`[不可判定]` 静态分析无法确定。")
    A("")
    A("**状态**：`CRIT` 明确矛盾或强标识 ｜ `RISK` 可被用于定位或关联 ｜ "
      "`INFO` 仅观测 ｜ `OK` 无泄漏 ｜ `SKIP` 未安装/不可用")
    A("")

    A("## 总览")
    A("")
    A("| 项 | 值 |")
    A("|---|---|")
    A(f"| CRIT | {sc['counts'][CRIT]} |")
    A(f"| RISK | {sc['counts'][RISK]} |")
    A(f"| INFO | {sc['counts'][INFO]} |")
    A(f"| OK | {sc['counts'][OK]} |")
    A(f"| SKIP | {sc['counts'][SKIP]} |")
    A(f"| **位置指纹暴露分（0-100）** | **{sc['exposure_score']}** |")
    A("")
    A("分项计分：CRIT=10、RISK=4，上限 100。分数只反映“客户端/服务端能看到多少可定位信号”，"
      "不代表封禁风险本身（封禁是服务端策略）。")
    A("")

    A("## 逐项结果")
    A("")
    for gid, gtitle in GROUPS:
        rows = [p for p in b.results if p.group == gid]
        if not rows:
            continue
        A(f"### {gid}. {gtitle}")
        A("")
        A("| ID | 探针 | 本机读数 | 状态 | 代码出处 | 去向 | 风险 |")
        A("|---|---|---|---|---|---|---|")
        for p in sorted(rows, key=lambda x: x.pid):
            val = p.value if isinstance(p.value, str) else json.dumps(p.value, ensure_ascii=False)
            val = val.replace("|", "\\|").replace("\n", " ")
            if len(val) > 180:
                val = val[:177] + "…"
            src = p.source.replace("|", "\\|").replace("\n", " ")
            ch = p.channel.replace("|", "\\|").replace("\n", " ")
            rk = p.risk.replace("|", "\\|").replace("\n", " ")
            A(f"| `{p.pid}` | {p.title} | {val or '—'} | **{p.status}** | {src} | {ch} | {rk} |")
        A("")

    # 一致性总结
    A("## 一致性判定")
    A("")
    f = b.facts
    A("| 维度 | 系统侧 | 网络侧 | 结论 |")
    A("|---|---|---|---|")
    tzv = f.get("tz_vs_ip") or {}
    _off = f.get("tz_offset")
    _off_s = ("UTC%+g" % _off) if isinstance(_off, (int, float)) else "—"
    if tzv:
        _verdict = "**一致**" if tzv.get("system") == tzv.get("ip") else "**不一致**"
    else:
        _verdict = "—"
    A(f"| 时区 | `{f.get('tz')}` ({_off_s}) | `{tzv.get('ip', '—')}` | {_verdict} |")
    geo_a = f.get("geo_a") or {}
    A(f"| 区域 | `{f.get('apple_locale')}` / {f.get('normalized_langs')} | "
      f"`{geo_a.get('country', '—')}` / `{geo_a.get('city', '—')}` | "
      f"{'一致' if str(f.get('apple_locale') or '').lower().endswith(str(geo_a.get('country') or '').lower()) and geo_a.get('country') else '需核对'} |")
    A(f"| ASN | — | `{f.get('asn_org', '—')}` | "
      f"{'**数据中心**' if f.get('is_datacenter') else '住宅/普通 ISP'} |")
    A(f"| PTR | — | `{f.get('ptr', '—')}` | {'**泄露托管商**' if f.get('ptr') else '无'} |")
    A(f"| VPN 判定 | — | vpnActive=`{f.get('vpn_active')}` | "
      f"connectedVPNs={f.get('vpn_connected')} |")
    A("")

    # 实测要点
    A("## 实测要点")
    A("")
    _tz = f.get("tz")
    _off = f.get("tz_offset")
    _off_s = ("UTC%+g" % _off) if isinstance(_off, (int, float)) else "?"
    _tzv = f.get("tz_vs_ip") or {}
    if _tzv:
        _tz_tail = ("，与出口 IP 时区**一致**" if _tzv.get("system") == _tzv.get("ip")
                    else "，**与出口 IP 时区不一致**")
    else:
        _tz_tail = ""
    A(f"- 系统时区 `{_tz}`（{_off_s}）{_tz_tail}；"
      f"它会出现在 `<env>` 提示词、Claude Code 子进程 `TZ`、`CRON_TZ` 和 Sentry `culture` 四处。")
    A(f"- 出口 `{f.get('ip4') or '—'}` ｜ ASN `{f.get('asn_org') or '—'}` ｜ "
      f"PTR `{f.get('ptr') or '—'}` ｜ 数据中心 = **{f.get('is_datacenter')}**")
    d17 = next((x for x in b.results if x.pid == "D17"), None)
    if d17 and isinstance(d17.value, dict) and d17.value.get("status"):
        A(f"- 边缘 `/api/hello` → HTTP {d17.value['status']}"
          + ("（**被拦**）" if d17.status == CRIT else "（未被拦）"))
    A(f"- 系统区域 `{f.get('apple_locale')}`，语言顺序 `{f.get('normalized_langs')}`")
    A(f"- `vpnActive = {f.get('vpn_active')}`——只由 `scutil --nc list` 的"
      f"已连接服务决定；本机 utun 命中 `{f.get('vpn_ifaces')}` 但**不**影响这个布尔值")
    _resid = [q for q in b.results
              if (q.group in ("A", "E") or q.pid in
                  ("F01", "F02", "F03", "F04", "F05", "F08"))
              and q.status in (CRIT, RISK)]
    A(f"- Claude 本机残留："
      + ("**有** → " + "、".join(f"`{q.pid}`" for q in _resid)
         if _resid else "无（A/E 组与 F01–F05 均为 OK/SKIP）"))
    _git = next((q for q in b.results if q.pid == "F06"), None)
    if _git and _git.status == RISK and isinstance(_git.value, dict):
        A(f"- git 全局身份 `{_git.value.get('user.name')}` / `{_git.value.get('user.email')}`"
          f"——不是 Claude 残留，但 CLI 会读 git/gh 凭据")
    A("")

    # 关键结论
    A("## 关键结论")
    A("")
    crit = [p for p in b.results if p.status == CRIT and p.weight != 0]
    if crit:
        A("### 明确暴露项")
        A("")
        for p in crit:
            val = p.value if isinstance(p.value, str) else json.dumps(p.value, ensure_ascii=False)
            A(f"- **`{p.pid}` {p.title}** — {val[:300]}")
            A(f"  - 出处：{p.source}")
            A(f"  - 去向：{p.channel}")
        A("")
    else:
        A("无 CRIT 项。")
        A("")

    A("### 客户端**没有**做的事（同样重要）")
    A("")
    A("- `[观测]` 桌面端与 CLI 都没有 GPS / `navigator.geolocation` 探针："
      "`getCurrentPosition` 命中 0 次；`enabled_geolocation:!1` 只是功能开关默认值，"
      "`geolocation: void 0` 在 entitlement 表里也未启用。")
    A("- `[观测]` 没有读取 `IOPlatformUUID` / 序列号：这两个值是系统层存在的，"
      "但本构建的 JS 未引用。")
    A("- `[观测]` 没有任何本地“封禁状态”文件：`policy-limits.json` 是唯一持久化的限制状态，"
      "带 24h TTL 且受组织策略新鲜度失效。")
    A("- `[观测]` 区域判定、账号封禁全部在服务端；客户端只做信号采集、错误码映射与自动补救。")
    A("")

    A("## 不可判定")
    A("")
    A("- 服务端如何对这些信号加权（时区 30%？ASN 50%？）——静态分析不可得。")
    A("- Cloudflare / 反滥用方使用哪家 IP 地理库、是否采信 RIR 归属。")
    A("- `client_attestation` 的服务端校验策略（是否比对历史设备公钥）。")
    A("- 跨账号聚合窗口长度（同一设备/同一 IP 多久内算同一人）。")
    A("")

    A("---")
    A("")
    A("本报告由只读脚本生成，未修改任何系统状态。")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


def render_json(b: Bench, path: Path) -> None:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "platform": sys.platform,
        "args": {k: v for k, v in vars(b.args).items()},
        "score": b.score(),
        "facts": {k: _jsonable(v) for k, v in b.facts.items()},
        "probes": [
            {
                "id": p.pid, "group": p.group, "title": p.title,
                "status": p.status,
                "value": _jsonable(p.value),
                "source": p.source, "channel": p.channel, "risk": p.risk,
                "note": p.note,
            }
            for p in sorted(b.results, key=lambda x: (x.group, x.pid))
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _jsonable(v: Any) -> Any:
    try:
        json.dumps(v)
        return v
    except Exception:  # noqa: BLE001
        if isinstance(v, dict):
            return {str(k): _jsonable(x) for k, x in v.items()}
        if isinstance(v, (list, tuple, set)):
            return [_jsonable(x) for x in v]
        return str(v)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Claude Desktop / CLI macOS 位置探测 Benchmark（只读）")
    ap.add_argument("--offline", action="store_true", help="跳过所有网络探针")
    ap.add_argument("--no-anthropic", action="store_true", help="跳过 /api/hello")
    ap.add_argument("--no-keychain", action="store_true", help="不查询 Keychain")
    ap.add_argument("--compact", action="store_true",
                    help="紧凑模式：每个探针只打一行（默认模式会打印完整细节）")
    ap.add_argument("--verbose", action="store_true", help="已废弃的别名，等价于默认模式")
    ap.add_argument("--md-out", default="claude-location-benchmark.md")
    ap.add_argument("--json-out", default="claude-location-benchmark.json")
    args = ap.parse_args()
    args.keychain = not args.no_keychain
    args.anthropic = not (args.no_anthropic or args.offline)

    b = Bench(args)
    b.group_a()
    b.group_b()
    b.group_c()
    b.group_d()
    b.group_e()
    b.group_f()
    b.group_g()

    render_console(b, compact=args.compact)
    if args.md_out:
        render_markdown(b, Path(args.md_out))
    if args.json_out:
        render_json(b, Path(args.json_out))
    print()
    print(f" 报告已写入: {args.md_out} / {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
