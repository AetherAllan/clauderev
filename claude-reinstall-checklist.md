# Claude 新账号环境终检清单

> 用法：每个 Gate 有 **验证命令** 与 **PASS 判据**。全部 PASS 才进入下一步。
> 标记：`[可验]` 本机可验证 / `[服务端]` 注册时才知道 / `[外部]` 依赖第三方数据

---

## 目录

- [Gate 0　先确认封禁层](#gate-0先确认封禁层决定后面是否值得做)
- [Gate 1　路径全集（先读这一节）](#gate-1路径全集先读这一节)
- [Gate 2　macOS 残留终检](#gate-2macos-残留终检可验)
- [Gate 3　Windows 残留终检](#gate-3windows-残留终检可验)
- [Gate 4　CLI 残留终检](#gate-4cli-残留终检可验)
- [Gate 5　系统环境对齐](#gate-5系统环境对齐mac--windows-都做可验)
- [Gate 6　网络](#gate-6网络可验--外部)
- [Gate 7　决定性项](#gate-7决定性项唯一能当场拒绝的因素)
- [Gate 8　安装纪律](#gate-8安装纪律)
- [Gate 9　注册后 72 小时](#gate-9注册后-72-小时)
- [最终自洽性验收](#最终自洽性验收)
- [不可判定项](#不可判定项本清单不覆盖)

---

## Gate 0　先确认封禁层（决定后面是否值得做）

| 项 | 你的情况 |
|---|---|
| 上次报错原文 / error code | `region policy` |
| 申诉状态 | 已永久关闭 |

**若为地区类拒绝码，机器清理的边际收益很低，重点在 Gate 7。**

| 拒绝码 | 层 | 机器清理有用吗 |
|---|---|---|
| `unsupported_phone_number_geo` | ② 地区 | ❌ 无用，只看号码 |
| `signups_disabled_in_region` | ② 地区 | ❌ 无用 |
| `region_missing` | ② 地区 | ❌ 无用 |
| `region_unavailable`（边缘） | ① 边缘 | ⚠️ 换 IP 有用 |
| `account_banned` | ④ 账号 | ❌ 无用，只能换账号 |
| `untrusted_device` / `bind_attestation_*` | ③ 设备 | ✅ 有用 |

---

## Gate 1　路径全集（先读这一节）

### 1.1 默认 appName = `Claude` `[观测]`

`extract/mac/asar/package.json`

```json
{
  "name": "@ant/desktop",
  "productName": "Claude",
  "desktopName": "com.anthropic.Claude.desktop",
  "version": "3.1623.0",
  "main": ".vite/build/index.pre.js"
}
```

Electron 的 `app.getPath("userData")` = `appData / app.getName()`，而 `getName()` 取 `productName` → **`Claude`**。

### 1.2 `-3p` 是有条件的，不是默认 `[观测]`

`extract/mac/asar/.vite/build/index.pre.js`

```js
if (!process.env.CLAUDE_USER_DATA_DIR) {
  if (XQ(Y), E0(u0())) {                      // ← 条件：是否第三方模式
    let e = UQ();
    if (T.app.getPath("userData") !== e) {
      T.app.setPath("userData", e);           // ← 仅在此分支覆盖
      try { p.default.mkdirSync(e, { recursive: !0, mode: 448 }) }
      catch(t){ Y.warn("[custom-3p] userData mkdir failed %s %s", e, String(t)) }
      T.app.setPath("crashDumps", h.default.join(e, "Crashpad"));
      process.platform === "darwin" && T.app.setAppLogsPath(n$());
    }
  } else u0().workspace.relocateUncUserData === !0 && (T.app.getPath("userData"), process.env)
}
```

判定链：

```js
function E0(e){ return T0(e) !== null }

function T0(e){
  return KU(e)
    ? ( x0(e) ? "chooser-disabled"
      : w0() === "1p" ? null                    // ← 第一方 → null → 不覆盖
      : ( aQ(e) ? "hybrid-pointer" : "persisted" ) )
    : null;                                     // ← 未激活第三方 → null
}

function KU(e){
  return GU ??= [...FU.values()].flatMap((e) => e.activatesThirdPartyMode ?? []),
         GU.some((t) => t(e, !1)) || oz(e) || XN(e).length > 0;
}

function w0(){
  if (C0 !== null) return C0.mode;
  try {
    let e = JSON.parse(p.readFileSync(ZQ(), "utf8"))[S0];
    C0 = { mode: e === "3p" || e === "1p" ? e : void 0 };
  } catch { C0 = { mode: void 0 } }
  return C0.mode;
}

var S0 = "deploymentMode", C0 = null, HQ = "claude_desktop_config.json";
function ZQ(){ return h.join(UQ(), HQ) }        // ← 在 3p 候选目录里读 deploymentMode
```

`UQ()` 负责算出 3p 路径：

```js
function UQ(){
  if (process.env.CLAUDE_USER_DATA_DIR) return T.app.getPath("userData");
  if (process.platform === "win32" && process.env.LOCALAPPDATA)
      return h.join(process.env.LOCALAPPDATA, VQ);      // → %LOCALAPPDATA%\Claude-3p
  let e = T.app.getPath("userData");
  return e.endsWith(IQ) ? e : `${e}${IQ}`;               // → <userData>-3p
}
var IQ = "-3p", LQ = "Claude", VQ = `${LQ}${IQ}`;        // VQ = "Claude-3p"
```

### 1.3 结论表

| `deploymentMode` | `KU()` 第三方激活 | 生效 userData |
|---|---|---|
| `"1p"` | 任意 | **`Claude`**（不覆盖） |
| 缺失 / `"3p"` | **false** | **`Claude`**（不覆盖，`T0` 返回 null） |
| 缺失 / `"3p"` | **true** | `Claude-3p` |

**普通官方安装属于前两行 → 目录是 `Claude`。**

### 1.4 完整路径表

| 平台 | 路径 | 何时存在 |
|---|---|---|
| **macOS** | `~/Library/Application Support/Claude` | **主目录（官方构建）** |
| macOS | `~/Library/Application Support/Claude-3p` | 仅第三方/混合模式 |
| **Windows** | `%APPDATA%\Claude` | **主目录（Electron 默认 appData）** |
| Windows | `%LOCALAPPDATA%\Claude-3p` | 第三方模式 |
| Windows | `%APPDATA%\Claude-3p` | 遗留 3p（`KQ()` 迁移源） |
| Windows | `%LOCALAPPDATA%\Claude-Data` | `QBe()` 的 `<name>-Data` 变体 |
| Windows | `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\` | MSIX 虚拟化 |
| Windows | `%LOCALAPPDATA%\Packages\AnthropicPBC.Claude_fnn82j28hfe8t\LocalCache\` | MSIX 另一发行 |
| Linux | `~/.config/Claude` | 主目录 |

**实践建议：全部检查。** 官方装完只有 `Claude`，但历史遗留或第三方渠道可能产生 `Claude-3p` / `Claude-Data`，而 Gate 8 的扫描逻辑会把它们都当作“可导入账号”。

### 1.5 同级目录会被主动扫描 `[观测]`

`index.chunk-CxzPVbs5.js` 的 `re()`

```js
let i = new Set([ c.app.getPath("appData") ]);
for (let t of i){
  let n = await readdir(t).catch(()=>[]);
  for (let i of n){
    if (!i.startsWith("Claude")) continue;              // ← 扫所有 Claude* 目录
    let n = join(t, i);
    n !== e && n !== r && await N(n) === "userData"
      && u({ label: P(i), rootPath: n, origin: "sibling-3p" });
  }
}
```

**只要目录名以 `Claude` 开头**（`Claude`、`Claude-3p`、`Claude-Data`、甚至 `Claude-备份`），都会被判定为“可导入的兄弟账号”并出现在界面上。

## Gate 2　macOS 残留终检 `[可验]`

> 主目录是 `~/Library/Application Support/Claude`（官方构建）。下面的命令用 `Claude*` 通配，能同时覆盖 `Claude-3p` 与历史遗留。

```bash
echo "=== 1. 所有 Claude* 同级目录（对应 re() 扫描）==="
ls -d ~/Library/Application\ Support/Claude* 2>/dev/null || echo "PASS 无"
for d in ~/Library/Application\ Support/Claude*; do
  [ -e "$d/ant-did" ] && echo "  ★ ant-did 存在: $d"
done

echo "=== 2. 确认代码实际使用的目录 ==="
ls -d ~/Library/Application\ Support/Claude-3p 2>/dev/null || echo "  不存在 Claude-3p"
ls -d ~/Library/Application\ Support/Claude    2>/dev/null || echo "  不存在 Claude"

echo "=== 3. HTTPStorages ==="
ls -d ~/Library/HTTPStorages/*[Aa]nthropic* 2>/dev/null || echo "PASS 无"
ls -d ~/Library/HTTPStorages/*[Cc]laude*    2>/dev/null || echo "PASS 无"

echo "=== 4. Containers / Group Containers / Saved State ==="
ls -d ~/Library/Containers/*[Cc]laude*            2>/dev/null || echo "PASS 无"
ls -d ~/Library/Group\ Containers/*[Cc]laude*     2>/dev/null || echo "PASS 无"
ls -d ~/Library/Saved\ Application\ State/*[Cc]laude* 2>/dev/null || echo "PASS 无"

echo "=== 5. Caches / Preferences / Logs（按 bundle id 命名）==="
# bundle id: com.anthropic.claudefordesktop
for d in \
  "$HOME/Library/Caches/com.anthropic.claudefordesktop" \
  "$HOME/Library/Caches/com.anthropic.claudefordesktop.ShipIt" \
  "$HOME/Library/Logs/Claude" \
  "$HOME/Library/Logs/Claude-3p" \
  "$HOME/Library/Preferences/com.anthropic.claudefordesktop.plist" \
  "$HOME/Library/Saved Application State/com.anthropic.claudefordesktop.savedState" \
  "$HOME/Library/HTTPStorages/com.anthropic.claudefordesktop" \
  "$HOME/Library/WebKit/com.anthropic.claudefordesktop"
do
  [ -e "$d" ] && echo "  FAIL 存在: $d" || echo "  PASS 无:   $d"
done
ls -d ~/Library/Caches/*[Cc]laude* 2>/dev/null
ls -d ~/Library/Logs/*[Cc]laude*   2>/dev/null

echo "=== 5b. 机器级 managed plist（App 会读它）==="
ls -la "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist" 2>/dev/null \
  || echo "PASS 无（若存在则可能强制策略）"

echo "=== 6. Keychain（四个名字都要查）==="
for svc in "Claude Code" "Claude Code-device-keys" "Claude Safe Storage" "Chrome Safe Storage"; do
  if security find-generic-password -s "$svc" >/dev/null 2>&1; then
    echo "  FAIL 存在: $svc"
  else
    echo "  PASS 无:   $svc"
  fi
done
# CLAUDE_CONFIG_DIR 设过时服务名带 -<8位hex> 后缀
echo "  -- 全库扫 Claude Code* --"
security dump-keychain 2>/dev/null | grep -i 'svce.*Claude Code' | head

echo "=== 7. App 本体 ==="
ls -d /Applications/*[Cc]laude* 2>/dev/null || echo "PASS 无"
ls -d ~/Applications/*[Cc]laude* 2>/dev/null || echo "PASS 无"

echo "=== 8. 启动失败日志（代码写在 tmpdir）==="
ls /tmp/claude-desktop-launch-failure-*.err 2>/dev/null || echo "PASS 无"

echo "=== 9. Chrome 状态（现代路径 Network/Cookies）==="
for f in $(find ~/Library/Application\ Support/Google/Chrome -maxdepth 3 -name "Cookies" 2>/dev/null); do
  echo "-- $f"
  cp "$f" /tmp/ck.db 2>/dev/null && sqlite3 /tmp/ck.db \
    "SELECT host_key,name FROM cookies WHERE host_key LIKE '%claude%' OR host_key LIKE '%anthropic%';" 2>/dev/null
done
find ~/Library/Application\ Support/Google/Chrome -maxdepth 4 \
  \( -iname "*claude*" -o -iname "*anthropic*" \) 2>/dev/null | head
echo "（无输出 = PASS）"
```

**PASS 判据**

| # | 项 | 期望 |
|---|---|---|
| 1 | 所有 `Claude*` 目录 | 不存在 |
| 3 | HTTPStorages | 不存在 |
| 4 | Containers / Group Containers / Saved State | 不存在 |
| 5 | Caches / Preferences / Logs | 不存在 |
| 6 | 四个 Keychain 条目 | 全部不存在（`Claude Safe Storage` 纯本地，可留但建议清） |
| 7 | Claude.app | 不存在 |
| 8 | 启动失败日志 | 不存在 |
| 9 | Chrome claude/anthropic cookie | 空 |

### `Claude Safe Storage` 与 `Chrome Safe Storage` 的区别 `[观测]`

`index.chunk-DbZjmJ_X.js`

```js
class N extends Error {
  constructor(e, t){
    super(`Chrome Safe Storage read failed: ${e}`), this.reason = e, this.osStatus = t;
  }
}
// [ChromeImport] claude-swift keychain binding unavailable
// [ChromeImport] Safe Storage key derivation failed
```

- `Chrome Safe Storage`：**Chrome 数据导入**功能会去读它（用于解密 Chrome 的 cookie/login data）
- `Claude Safe Storage`：Desktop 自己的 Electron `safeStorage` 密钥

两者都会被创建，但**只有前者代表“本机曾导入过浏览器数据”**。

---

### 2.1 一次性清理命令

```bash
rm -rf -- \
  "$HOME/.claude.json" \
  "$HOME/.claude.json.taptap-maker.bak.latest" \
  "$HOME/Library/Caches/com.anthropic.claudefordesktop" \
  "$HOME/Library/Caches/com.anthropic.claudefordesktop.ShipIt" \
  "$HOME/Library/Logs/Claude"
```

补齐其余同类残留：

```bash
rm -rf -- \
  "$HOME/Library/Application Support/Claude" \
  "$HOME/Library/Application Support/Claude-3p" \
  "$HOME/Library/Preferences/com.anthropic.claudefordesktop.plist" \
  "$HOME/Library/Saved Application State/com.anthropic.claudefordesktop.savedState" \
  "$HOME/Library/HTTPStorages/com.anthropic.claudefordesktop" \
  "$HOME/Library/WebKit/com.anthropic.claudefordesktop" \
  "$HOME/.claude" \
  "$HOME/.claude.json.corrupted" \
  "$HOME/.claude.json.backup"
```

Keychain：

```bash
for svc in "Claude Code" "Claude Code-device-keys" "Claude Safe Storage" "Chrome Safe Storage"; do
  security delete-generic-password -s "$svc" >/dev/null 2>&1 && echo "删除: $svc" || echo "无:   $svc"
done
```

> `.taptap-maker.bak.latest` 的后缀来自第三方备份工具，不是 Anthropic 的命名。它同样是 `~/.claude.json` 的完整副本，含同样的身份字段，所以要一并删。

## Gate 3　Windows 残留终检 `[可验]`

```powershell
Write-Host "=== 1. 所有 Claude* 同级目录（对应 re() 扫描）==="
@("$env:LOCALAPPDATA", "$env:APPDATA") | ForEach-Object {
  Get-ChildItem $_ -Directory -Filter "Claude*" -ErrorAction SilentlyContinue |
    ForEach-Object { "  发现: $($_.FullName)" }
}

Write-Host "`n=== 2. 四个路径变体 ==="
$paths = @(
  "$env:LOCALAPPDATA\Claude-3p",
  "$env:LOCALAPPDATA\Claude-Data",
  "$env:APPDATA\Claude",
  "$env:LOCALAPPDATA\Packages\Claude_pzs8sxrjxfjjc\LocalCache",
  "$env:LOCALAPPDATA\Packages\AnthropicPBC.Claude_fnn82j28hfe8t\LocalCache"
)
foreach ($p in $paths) {
  $ok = Test-Path $p
  Write-Host ("{0,-8} {1}" -f $(if($ok){"存在"}else{"不存在"}), $p)
  if ($ok) {
    Get-ChildItem $p -Filter "ant-did" -Recurse -ErrorAction SilentlyContinue |
      ForEach-Object { "        ★ ant-did: $($_.FullName)" }
  }
}

Write-Host "`n=== 3. 凭据管理器 ==="
cmdkey /list | Select-String -Pattern "anthropic|claude"
Write-Host "（无输出 = PASS）"

Write-Host "`n=== 4. 注册表 ==="
@("HKCU:\Software\Anthropic","HKLM:\Software\Anthropic") | ForEach-Object {
  if (Test-Path $_) { "FAIL 存在: $_" } else { "PASS 无: $_" }
}

Write-Host "`n=== 5. App 本体 / MSIX 注册 ==="
Get-AppxPackage *anthropic* | Select-Object Name, PackageFullName
Get-ChildItem "$env:LOCALAPPDATA\Programs" -Filter "*laude*" -ErrorAction SilentlyContinue
Write-Host "（无输出 = PASS）"

Write-Host "`n=== 6. 计划任务 / 服务 ==="
Get-ScheduledTask | Where-Object { $_.TaskName -like "*laude*" -or $_.TaskName -like "*nthropic*" }
Get-Service | Where-Object { $_.Name -like "*cowork*" -or $_.DisplayName -like "*laude*" }
Write-Host "（无输出 = PASS）"
```

---

## Gate 4　CLI 残留终检 `[可验]`

### 4.1 `~/.claude.json` —— 全局配置，CLI 的身份主源 `[观测]`

**注意：这是 `~/.claude.json` 一个文件，不是 `~/.claude/` 目录。** 两者并存。

`/tmp/claude_strings.txt`

```js
function h0(e, n){                        // getUserID
  let r = ce(), s = ue();
  if (typeof s.userID === "string" && Fs.test(s.userID)) return s.userID;
  if (r.generatedUserID) return r.generatedUserID;
  let h = n !== void 0 && Fs.test(n) ? n : Ju(32).toString("hex");
  return r.setGeneratedUserID(h), Ae((y) => ({ ...y, userID: h })), h;
}

function FSt(e){                          // getOrCreateMachineId
  let n = ce(), r = ue();
  if (typeof r.machineID === "string" && Fs.test(r.machineID)) return r.machineID;
  if (n.generatedMachineID) return n.generatedMachineID;
  let s = Ju(32).toString("hex");
  return n.setGeneratedMachineID(s), Ae((h) => ({ ...h, machineID: s })), s;
}

var Fs = /^[0-9a-f]{64}$/;                // ← 64 位十六进制
```

`userID` / `machineID` 均为 **32 字节随机数 → 64 位十六进制**。

### 4.2 `~/.claude.json` 字段全集 `[观测]`

| 字段 | 命中数 | 含义 |
|---|---|---|
| `userID` | 6 | 64-hex 持久用户标识 |
| `machineID` | 5 | 64-hex 持久机器标识 |
| `oauthAccount` | 84 | 已登录账号信息 |
| `projects` | 708 | **项目路径记录** |
| `mcpServers` | 322 | **MCP 服务器配置** |
| `githubRepoPaths` | 8 | **仓库 → 本地路径映射** |
| `customApiKeyResponses` | 11 | 自定义 API key 的批准/拒绝记录 |
| `pastedContents` | 183 | 粘贴内容缓存 |
| `numStartups` | 33 | 启动次数 |
| `installMethod` | 32 | **安装渠道（对应 `installer_variant`）** |
| `tipsHistory` | 13 | 提示历史 |
| `hasCompletedOnboarding` | 21 | 引导完成标记 |
| `lastOnboardingVersion` | 4 | — |
| `migrationVersion` | 7 | 配置迁移版本 |
| `cachedChangelog` | 6 | — |
| `changelogLastFetched` | 2 | — |
| `autoUpdates` | 65 | — |

**这份文件里有：账号身份、机器身份、项目路径、MCP 配置、GitHub 仓库映射、安装渠道。**

### 4.3 配置备份文件 `[观测]`

```
" in ~/.claude.json: its value is not valid for this setting, so ...
.corrupted.
Could not back up corrupted config (\n); continuing.
globalConfigCopy4
Error getting AWS credentials from awsCredentialExport (in settings or ~/.claude.json):
```

存在 `.corrupted` 与 `globalConfigCopy4` 这类备份。**删主文件时这些也要一并清掉**，否则旧值可能被回填。

### 4.4 `~/.claude/` 目录 `[观测]`

```
<configDir>/.device-keys        ← 设备密钥降级路径
```

`CLAUDE_CONFIG_DIR` 可改变该位置。

### 4.5 验证命令

```bash
echo "=== 1. 全局配置文件及其全部备份变体 ==="
for f in \
  "$HOME/.claude.json" \
  "$HOME/.claude.json.corrupted" \
  "$HOME/.claude.json.backup" \
  "$HOME/.claude.json.taptap-maker.bak.latest"
do
  [ -e "$f" ] && echo "  FAIL 存在: $f" || echo "  PASS 无:   $f"
done
# 兜底：任何 .claude.json* 变体
ls -la "$HOME"/.claude.json* 2>/dev/null || echo "  PASS 无任何 .claude.json* 变体"

echo "=== 2. 里面有身份字段吗 ==="
[ -f ~/.claude.json ] && python3 - <<'PY'
import json,os
p=os.path.expanduser('~/.claude.json')
try: d=json.load(open(p))
except Exception as e: print('  解析失败:',e); raise SystemExit
for k in ['userID','machineID','oauthAccount','projects','mcpServers',
          'githubRepoPaths','installMethod','numStartups','customApiKeyResponses']:
    v=d.get(k)
    if v is None: continue
    if isinstance(v,(dict,list)):
        print(f"  {k}: <{type(v).__name__}, {len(v)} 项>")
    else:
        s=str(v)
        print(f"  {k}: {s[:40]+'…' if len(s)>40 else s}")
PY

echo "=== 3. CLI 配置目录 ==="
ls -d ~/.claude 2>/dev/null || echo "PASS 无 ~/.claude"
ls -la ~/.claude/.device-keys 2>/dev/null || echo "PASS 无 .device-keys"
ls -d ~/.config/claude* 2>/dev/null || echo "PASS 无 ~/.config/claude*"

echo "=== 4. CLI 二进制 ==="
command -v claude || echo "PASS 未安装"
ls /opt/homebrew/bin/ 2>/dev/null | grep -i claude || echo "PASS brew 无"
npm ls -g --depth=0 2>/dev/null | grep -i claude || echo "PASS npm 无"
```

**PASS 判据**：`~/.claude.json`、其备份、`~/.claude/`、CLI 二进制**全部不存在**。

### 4.6 CLI 凭据库的命名规则 `[观测]`

`index.chunk-Ghv0q1hg.js`

```js
var cke = "-credentials";

function lke(e = ""){
  let t = process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR,
      n = t === void 0 ? !process.env.CLAUDE_CONFIG_DIR : !t,
      r = t === void 0 ? bf() : t.normalize("NFC"),
      i = n ? "" : `-${createHash("sha256").update(r).digest("hex").substring(0, 8)}`;
  return `Claude Code${Lte().OAUTH_FILE_SUFFIX}${e}${i}`;
}

function dke(){
  if (process.platform === "win32") return "claude-code-user";
  let e;
  try { e = process.env.USER || userInfo().username } catch { e = "claude-code-user" }
  return uke.test(e) ? e : "claude-code-user";      // uke = /^[a-zA-Z0-9._-]+$/
}
```

且 `OAUTH_FILE_SUFFIX: ""`。

**含义**

| 项 | 值 |
|---|---|
| Keychain / 凭据管理器服务名 | `Claude Code`（`CLAUDE_CONFIG_DIR` 被设时追加 `-<sha256 前8位>`） |
| 账号名 | macOS/Linux = `$USER`；Windows = `claude-code-user` |
| 相关常量 | `-credentials`（文件后缀） |

**macOS 上要查的 Keychain 条目因此有三个：**

```bash
security find-generic-password -s "Claude Code"             2>&1 | head -3
security find-generic-password -s "Claude Code-device-keys" 2>&1 | head -3
security find-generic-password -s "Claude Safe Storage"     2>&1 | head -3
# 若设过 CLAUDE_CONFIG_DIR，服务名会带 -<8位hex> 后缀：
security dump-keychain | grep -i "Claude Code"
```

### 4.6 GitHub 集成面 `[观测]`

```
githubRepoPaths            ← 仓库 → 本地路径映射
github_app_suspended
github_app_not_installed
DISABLE_INSTALL_GITHUB_APP_COMMAND
GH_TOKEN / GITHUB_TOKEN
gh auth token
[0mcould not determine executable to run for package ...
api.github.com    GITHUB_API_DOMAIN
```

**如果本机曾连接 GitHub App 并授权访问私有仓库**，相关痕迹有三处：

| 位置 | 内容 |
|---|---|
| `~/.claude.json` → `githubRepoPaths` | 哪些仓库被映射到本地哪个路径 |
| GitHub 侧 | 已安装的 App 授权（**需在 GitHub 账号设置里手动撤销**） |
| `gh` CLI 凭据 | `gh auth token`（若用过） |

```bash
# 检查本机 gh 凭据
gh auth status 2>&1 | head
# 撤销需在 GitHub 网页侧：Settings → Applications → Installed GitHub Apps
```

---

## Gate 5　系统环境对齐（Mac + Windows 都做）`[可验]`

### 目标：五者同国

```
出口 IP 国  =  系统时区  =  locale  =  号码归属国  =  支付方式国
```

### macOS

```bash
sudo systemsetup -gettimezone
defaults read -g AppleLanguages
defaults read -g AppleLocale
echo "TZ=${TZ:-<未设置>}"
date
```

```bash
sudo systemsetup -settimezone "America/New_York"
defaults write -g AppleLanguages -array "en-US" "zh-Hans"
defaults write -g AppleLocale -string "en_US"
grep -n "TZ=" ~/.zshrc ~/.zprofile 2>/dev/null
```

### Windows

```powershell
Get-TimeZone; Get-WinSystemLocale; Get-WinUserLanguageList
Set-TimeZone -Id "Eastern Standard Time"
Set-WinSystemLocale en-US
Set-WinUserLanguageList en-US -Force
```

**PASS 判据**

| 项 | 期望 |
|---|---|
| 时区 | 目标国时区 |
| 语言首位 | `en-US` |
| 区域格式 | `en_US` |
| `TZ` 环境变量 | 与系统时区一致（或未设置） |
| `date` 输出 | 目标国时间 |

> 代码依据：`app.getPreferredSystemLanguages()` 返回**有序列表**，空时才 fallback；Desktop 主进程读 OS 时区，CLI 把 `TZ` 传给子进程。改完**重启应用**。

### 5.1 语言列表不止进 prompt，还会直接给到渲染进程 `[观测]`

`index.chunk-BfOAx4v9.js` 的 `NK()`

```js
var JUr = "--desktop-managed-config=";

function YUr(e){                       // ← 语言规范化
  let t = [];
  for (let n of e){
    let e = n.split(/[.@]/, 1)[0].replace(/_/g, "-");    // en_US.UTF-8 → en-US
    e === "" || e === "C" || e === "POSIX" || t.includes(e) || t.push(e);
  }
  return t;
}

function NK(){
  let e = G();
  return `${JUr}${JSON.stringify({
    ...sKe(),
    deploymentMode: e.type,
    appVersion: a.app.getVersion(),
    cookielessOrigin: e.type === "3p",
    deploymentOrganizationUuid: e.telemetryOrgUuid() ?? void 0,
    deviceClass: NVt,
    preferredSystemLanguages: YUr(a.app.getPreferredSystemLanguages()),
    ...iKt()
  })}`;
}
```

这条字符串会被塞进 `process.argv`，主进程再通过预加载脚本暴露给页面：

`index.chunk-*/mainView.js`

```js
let n = process.argv.find((e) => e.startsWith(Al));
if (n) try {
  let e = JSON.parse(n.slice(Al.length));
  t.contextBridge.exposeInMainWorld("desktopManagedConfig", e);
  t.contextBridge.exposeInMainWorld("desktopEnterpriseConfig", e);
  t.contextBridge.exposeInMainWorld("desktopTelemetryConfig", e);
  t.contextBridge.exposeInMainWorld("desktopDeviceClass", e.deviceClass);
  t.contextBridge.exposeInMainWorld("desktopPreferredLanguages", e.preferredSystemLanguages);
} catch {}
```

**含义（重要）**

- 远端 `claude.ai` 页面可以通过 `window.desktopPreferredLanguages` / `window.desktopDeviceClass` **直接读到你的系统语言列表与设备类别**，不需要经过系统提示词；
- 规范化规则：去掉 `.` / `@` 之后的后缀、`_` → `-`、过滤 `C` / `POSIX`、去重；
- 同时暴露 `deploymentMode`、`cookielessOrigin`、`deploymentOrganizationUuid`、`appVersion`。

**实践推论**：只改 prompt 层或只改系统时区不够——**语言列表在页面层可见**。Gate 5 里把 `en-US` 排在首位这一步是必需的，不是可选的。


---

## Gate 6　网络 `[可验]` + `[外部]`

### 6.1 本机不留 VPN 痕迹（macOS 专属）

```bash
scutil --nc list
ifconfig | grep -E '^(utun|ppp|ipsec|tun)[0-9]+:'
pgrep -x bootpd && echo "WARN bootpd 在跑" || echo "PASS"
ifconfig | grep -E '^(bridge|vmnet)[0-9]+:'
```

**PASS 判据**：`scutil --nc list` 无 `(Connected)` 项；`utun*` 仅系统必需或不存；`bootpd` 未运行；`bridge*`/`vmnet*` 不存在。

> Windows 侧这些探测是死代码（`process.platform!=="darwin"` 早退）。

### 6.2 IP 与 ASN 声誉 `[外部]`

```bash
curl -s https://ipinfo.io/json
```

**PASS 判据**：`country` 与 Gate 5 同国；`org` 是**住宅 ISP**；未被标为 proxy/VPN。

---

## Gate 7　决定性项（唯一能“当场拒绝”的因素）

| 项 | 状态 |
|---|---|
| 身份提供者账号 | 新 Outlook |
| **号码归属地** | ❓ 未定 |
| 支付方式国 | ❓ 未定 |

`unsupported_phone_number_geo` 是**零历史硬规则**。`RegionSupport` 两布尔决定走哪条路 `[服务端]`：

```java
l("claudeai_supported", true);
l("phone_verification_supported", true);
```

| `phone_verification_supported` | 路径 | 号码是否一票否决 |
|---|---|---|
| `false` | 邮箱验证，Outlook 够用 | 不会 |
| `true` | 必须手机验证 | 会 |

**支付同理**：`Google Play → BillingConfig.countryCode`、`Apple IAP → StoreKit storefront`、`Web → 卡 BIN 国家`。换厂商不等于消除。**不要出现“美国 IP + 中国卡”。**

---

## Gate 8　安装纪律

| 项 | 要求 | 原因 |
|---|---|---|
| 只装桌面客户端 | ✅ | Android 信号面最差（`carrier_name` + Play 国家 + 号码 geo） |
| **不要手动重置 `ant-did`** | ✅ | 见 Gate 9 的说明 |
| 不装反指纹浏览器 | ✅ | 必然留下矛盾组合 |
| 不装改 UA 插件 | ✅ | 只改 1 项，余下 8 项矛盾 |
| 不注册系统级 VPN（Mac） | ✅ | `scutil` / `utun*` 会被探测 |
| **保持原安装渠道** | ✅ | 目录名 `-3p` / MSIX PFN 会影响 `installer_variant`、`store_build` |
| **清掉所有 `Claude*` 同级目录** | ✅ | `re()` 会扫描并列出为“可导入账号” |
| Windows / Mac 各自原生自洽 | ✅ | 不要互相伪装成同一台 |

### 关于渠道一致性 `[观测]`

```js
.map(e => /^3p$/i.test(e) ? "3P" : e)
Vl = `${Bl}${zl}`                  // "Claude-3p"
IVe = [ "Claude_pzs8sxrjxfjjc", "AnthropicPBC.Claude_fnn82j28hfe8t" ]
```

目录名后缀与 MSIX PFN 会被计入 `installer_variant` / `store_build` 并上报。**换渠道会改变这一项**，而它属于“本该稳定”的信号。建议保持原渠道。

### 关于 `ant-did` 的真实语义 `[观测]`

```js
function KVt(){
  try {
    let e = n.default.resolve(a.app.getPath("userData"), XBe);
    try {
      let t = WVt(e);                       // base64 解码 + UUID 正则校验
      if (t !== void 0) return t;
      let n = o.default.lstatSync(e);
      if (!n.isFile() || n.nlink > 1) throw Error("ant-did is not a plain file");
      o.default.rmSync(e);                  // ← 内容无效则删除
    } catch(e){ if (e?.code !== "ENOENT") throw e }
    let t = (0, f.randomUUID)();
    try { GVt(e, t); }                      // flag:"wx", mode 384(0600)
    catch(t){
      if (t?.code === "EEXIST") { let t = WVt(e); if (t !== void 0) return t }
      throw t;
    }
    return t;
  } catch(e){
    BVt = !1;
    return N.error("Failed to read or write install file", e), (0, f.randomUUID)();
  }
}
```

`nlink > 1` 的语义是「内容无效 → 删除并重建」。

**末端兜底值得注意**：读写失败时返回**不落盘的临时 UUID** 并置 `BVt=false`。这个 UUID 每次启动都会变 → 表现为“设备身份不稳定”，服务端可能视为异常。

**实践含义**：清理后**不要手动干预** `ant-did`。装新版会自动生成一个全新且有效的。

---

## Gate 9　注册后 72 小时

| 项 | 要求 |
|---|---|
| 首日强度 | 不要撞限额，先少量正常对话 |
| 提示词风格 | 不要复用旧账号的写法与句式 |
| 双机切换 | Windows/Mac 不要短时间密集交替登录 |
| **观察指标** | **新号能撑多久 = 评分累积的时间尺度** |

**诊断价值**：数天内再次被处理 → 落在评分层，关联锚点不在设备；当场被拒 → 硬规则（号码或地区）。

---

## 最终自洽性验收

| 检查 | 要求 |
|---|---|
| IP 国 = 时区国 = locale 国 = 号码国 = 支付国 | 五项必须一致 |
| 硬件 | **不变是正常的**，不要改（低熵、不承担身份） |
| `ant-did` | 全新生成即可，不要干预 |
| 安装渠道 | 与旧安装保持一致 |
| 行为模式 | 唯一换不掉、也唯一必须变化的一项 |

---

## 不可判定项（本清单不覆盖）

| 项 | 原因 |
|---|---|
| region policy 封禁记在账号还是身份指纹 | 服务端 |
| 过闸后是否有冷却期 / 观察期 | 服务端 |
| 跨账号聚合的维度与时间窗 | 服务端 |
| 你的地区 `phone_verification_supported` 取值 | 服务端按当下信号算 |
| 号码支持国名单 | 服务端表 |
| IP 是否被情报库标记 | 外部数据 |
| 新 Outlook 是否被旧账号关联 | Microsoft 侧 + 服务端 |
| 硬件画像在评分中的实际权重 | 服务端 |
| `machineID` / `userID` 是否参与跨账号关联 | 客户端只上报，判定不可见 |
| `githubRepoPaths` 是否被上报 | 字段存在，是否上送不可判定 |

---

## 关键代码位置速查

| 主题 | 文件 | 符号 |
|---|---|---|
| appName / productName | `package.json` | `productName: "Claude"` |
| userData 覆盖条件 | `index.pre.js` | `E0()` / `T0()` / `KU()` / `w0()` |
| 3p 路径 | `index.pre.js` | `UQ()` / `IQ` / `VQ` |
| deploymentMode | `index.pre.js` | `ZQ()` / `HQ` / `S0` |
| ant-did 读写 | `index.chunk-BfOAx4v9.js` | `KVt()` / `XBe` / `GVt()` |
| 同级目录扫描 | `index.chunk-CxzPVbs5.js` | `re()` |
| 语言规范化 + argv 注入 | `index.chunk-BfOAx4v9.js` | `YUr()` / `NK()` / `JUr` |
| 渲染进程桥 | `index.chunk-*/mainView.js` | `exposeInMainWorld("desktopPreferredLanguages")` |
| VPN 探测 | `index.chunk-BfOAx4v9.js` | `I2r()` / `L2r()` / `R2r()` / `z2r()` |
| 遥测 envelope | `index.chunk-BfOAx4v9.js` | `jAn()` / `Kv()` |
| CLI 身份 | `/tmp/claude_strings.txt` | `h0()` / `FSt()` / `Fs` |
| CLI 凭据库名 | `index.chunk-Ghv0q1hg.js` | `lke()` / `dke()` / `cke` |
| CLI 设备密钥 | `/tmp/claude_strings.txt` | `Claude Code-device-keys` |
| policy limits | `index.chunk-DIjipm-e.js` | 整模块 |
| bundle id | `index.chunk-Zgtg6mFJ.js` | `K = "com.anthropic.claudefordesktop"` |
| ShipIt 缓存路径 | `index.chunk-BfOAx4v9.js` | `wti()` / `Sti` |
| managed plist | `index.chunk-BfOAx4v9.js` | `cWe()` |
| 日志目录 | `index.pre.js` | `n$()` |
