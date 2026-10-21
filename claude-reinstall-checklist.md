# Claude 新账号环境终检清单

> 用法：每个 Gate 都有 **验证命令** 与 **PASS 判据**。全部 PASS 才进入下一步。
> 标记：`[可验]` 本机能验证 / `[服务端]` 只能注册时才知道 / `[外部]` 依赖第三方数据

---

## Gate 0　先确认封禁层（决定后面是否值得做）

| 项 | 你的情况 |
|---|---|
| 上次报错原文 / error code | `region policy` |
| 申诉状态 | 已永久关闭 |

**若为地区类拒绝码，机器清理的边际收益很低，重点在 Gate 5。**

| 拒绝码 | 层 | 机器清理有用吗 |
|---|---|---|
| `unsupported_phone_number_geo` | ② 地区 | ❌ 无用，只看号码 |
| `signups_disabled_in_region` | ② 地区 | ❌ 无用 |
| `region_missing` | ② 地区 | ❌ 无用 |
| `region_unavailable`（边缘） | ① 边缘 | ⚠️ 换 IP 有用 |
| `account_banned` | ④ 账号 | ❌ 无用，只能换账号 |
| `untrusted_device` / `bind_attestation_*` | ③ 设备 | ✅ 有用 |

---

## Gate 1　macOS 残留终检 `[可验]`

一条命令跑完全部：

```bash
echo "=== 1. userData / ant-did"
ls -d ~/Library/Application\ Support/*[Cc]laude* 2>/dev/null || echo "PASS 无"
ls -d ~/Library/Application\ Support/*[Aa]nthropic* 2>/dev/null || echo "PASS 无"

echo "=== 2. HTTPStorages"
ls -d ~/Library/HTTPStorages/*[Aa]nthropic* 2>/dev/null || echo "PASS 无"

echo "=== 3. Containers"
ls -d ~/Library/Containers/*[Cc]laude* 2>/dev/null || echo "PASS 无"
ls -d ~/Library/Group\ Containers/*[Cc]laude* 2>/dev/null || echo "PASS 无"

echo "=== 4. Saved State / Caches / Preferences"
ls -d ~/Library/Saved\ Application\ State/*[Cc]laude* 2>/dev/null || echo "PASS 无"
ls -d ~/Library/Caches/*[Cc]laude* 2>/dev/null || echo "PASS 无"
ls ~/Library/Preferences/*anthropic* 2>/dev/null || echo "PASS 无"

echo "=== 5. CLI 配置"
ls -d ~/.claude 2>/dev/null || echo "PASS 无"
ls ~/.claude/.device-keys 2>/dev/null || echo "PASS 无"

echo "=== 6. Keychain（两条都要无）"
security find-generic-password -s "Claude Code-device-keys" 2>&1 | grep -q "could not be found" && echo "PASS 无设备密钥" || echo "FAIL 存在设备密钥"
security find-generic-password -s "Claude Safe Storage" 2>&1 | grep -q "could not be found" && echo "PASS 无 safeStorage" || echo "WARN 存在 safeStorage（纯本地，可留可删）"

echo "=== 7. App 本体"
ls -d /Applications/*[Cc]laude* 2>/dev/null || echo "PASS 无"
ls -d ~/Applications/*[Cc]laude* 2>/dev/null || echo "PASS 无"

echo "=== 8. CLI 二进制"
command -v claude || echo "PASS 未安装"
ls /opt/homebrew/bin/ 2>/dev/null | grep -i claude || echo "PASS brew 无"
npm ls -g --depth=0 2>/dev/null | grep -i claude || echo "PASS npm 无"

echo "=== 9. Chrome 状态（现代路径是 Network/Cookies）"
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
| 1 | userData / `ant-did` | 不存在 |
| 2 | HTTPStorages | 不存在 |
| 3 | Containers / Group Containers | 不存在 |
| 4 | Saved State / Caches / Preferences | 不存在 |
| 5 | `~/.claude` / `.device-keys` | 不存在 |
| 6 | `Claude Code-device-keys` | 不存在 |
| 7 | Claude.app | 不存在 |
| 8 | CLI 二进制 | 不存在 |
| 9 | Chrome claude/anthropic cookie | 空 |

若 9 非空 → 删整个 profile，或用全新 profile / 全新浏览器专供新账号（逐条删易漏 `Network Persistent State`、`TransportSecurity`、`Web Data`）。

---

## Gate 2　Windows 残留终检 `[可验]`

```powershell
Write-Host "=== 1. userData"
"$env:APPDATA\Claude", "$env:LOCALAPPDATA\Claude" | ForEach-Object {
  if (Test-Path $_) { "FAIL 存在: $_" } else { "PASS 无: $_" }
}
if (Test-Path "$env:APPDATA\Claude\ant-did") { "FAIL ant-did 存在" } else { "PASS ant-did 无" }

Write-Host "=== 2. CLI 配置"
if (Test-Path "$env:USERPROFILE\.claude") { "FAIL 存在" } else { "PASS 无" }

Write-Host "=== 3. 凭据管理器"
cmdkey /list | Select-String -Pattern "anthropic|claude"
Write-Host "（无输出 = PASS）"

Write-Host "=== 4. 注册表"
if (Test-Path "HKCU:\Software\Anthropic") { "FAIL 存在" } else { "PASS 无" }
if (Test-Path "HKLM:\Software\Anthropic") { "FAIL 存在" } else { "PASS 无" }

Write-Host "=== 5. App 本体"
Get-AppxPackage *anthropic* | Select-Object Name, PackageFullName
Get-ChildItem "$env:LOCALAPPDATA\Programs" -Filter "*laude*" -ErrorAction SilentlyContinue
Write-Host "（无输出 = PASS）"

Write-Host "=== 6. 计划任务 / 服务（cowork-svc）"
Get-ScheduledTask | Where-Object { $_.TaskName -like "*laude*" -or $_.TaskName -like "*nthropic*" }
Get-Service | Where-Object { $_.Name -like "*cowork*" -or $_.DisplayName -like "*laude*" }
Write-Host "（无输出 = PASS）"
```

**PASS 判据**：全项不存在。

> Windows 侧注意 `Get-AppxPackage` —— MSIX 卸载后可能仍有包注册残留；`cowork-svc.exe` 是 Desktop 的服务组件，卸载后应无对应服务。

---

## Gate 3　系统环境对齐（Mac + Windows 都做） `[可验]`

### 目标：五者同国

```
出口 IP 国  =  系统时区  =  locale  =  号码归属国  =  支付方式国
```

### macOS

```bash
# 时区
sudo systemsetup -gettimezone

# 语言列表（顺序重要！首位决定命中）
defaults read -g AppleLanguages

# 区域格式
defaults read -g AppleLocale

# TZ 环境变量（CLI 用它传子进程，必须与系统时区一致）
echo "TZ=${TZ:-<未设置>}"

# 实际生效
date
```

改法：

```bash
sudo systemsetup -settimezone "America/New_York"

# 语言：en-US 必须在首位
defaults write -g AppleLanguages -array "en-US" "zh-Hans"
defaults write -g AppleLocale -string "en_US"

# TZ 一致性：若 shell rc 里设过 TZ，注释掉或改成同名
grep -n "TZ=" ~/.zshrc ~/.zprofile 2>/dev/null
```

> 代码依据：`app.getPreferredSystemLanguages()` 返回**有序列表**，空时才 fallback 到 `app.getLocale()`；只加语言不排首位无效。Desktop 主进程读 OS 时区，CLI 把 `TZ` 传给子进程 —— 两者不一致会造成同一次会话里自相矛盾。

### Windows

```powershell
Get-TimeZone
Get-WinSystemLocale
Get-WinUserLanguageList

Set-TimeZone -Id "Eastern Standard Time"
Set-WinSystemLocale en-US
Set-WinUserLanguageList en-US -Force
```

**PASS 判据**

| 项 | 期望 |
|---|---|
| 时区 | 目标国时区（如 `America/New_York` / Eastern） |
| 语言首位 | `en-US` |
| 区域格式 | `en_US` |
| `TZ` 环境变量 | 与系统时区一致（或未设置） |
| `date` 输出 | 目标国时间 |

改完**重启应用**（否则不会重新读）。

---

## Gate 4　网络 `[可验]` + `[外部]`

### 4.1 本机不留 VPN 痕迹（macOS 专属，代码会探测）

```bash
# 系统 VPN 配置（代码匹配 (Connected)）
scutil --nc list

# VPN 网卡（代码匹配 utun\d+|ppp\d+|ipsec\d+|tun\d+）
ifconfig | grep -E '^(utun|ppp|ipsec|tun)[0-9]+:'

# 互联网共享
pgrep -x bootpd && echo "WARN bootpd 在跑" || echo "PASS"

# 虚拟网桥（代码匹配 bridge\d+|vmnet\d+）
ifconfig | grep -E '^(bridge|vmnet)[0-9]+:'
```

**PASS 判据**

| 项 | 期望 |
|---|---|
| `scutil --nc list` | 无 `(Connected)` 项 |
| `utun*` | 不存在，或仅系统必需且非 VPN |
| `bootpd` | 未运行 |
| `bridge*` / `vmnet*` | 不存在 |

> 做法：走**路由器级 / 透明代理**，本机不注册系统 VPN 配置、不产生 `utun` 网卡。
> Windows 侧这些探测是死代码（`process.platform!=="darwin"` 早退），无需处理。

### 4.2 IP 与 ASN 声誉 `[外部]`

```bash
curl -s https://ipinfo.io/json
# 关注：country / org / asn
```

**PASS 判据**

| 项 | 期望 |
|---|---|
| `country` | 与 Gate 3 时区同国 |
| `org` | **住宅 ISP**，不是 IDC / hosting / cloud |
| 代理库标记 | 未被标为 proxy / VPN（需第三方库查） |

> 住宅 IP 但被情报库标记为代理，**比干净的机房 IP 更糟**。

---

## Gate 5　决定性项（唯一能"当场拒绝"的因素）

| 项 | 状态 | 说明 |
|---|---|---|
| 身份提供者账号 | ✅ 新 Outlook | 当前最有价值的一步 |
| **号码归属地** | ❓ **未定** | 见下 |
| 支付方式国 | ❓ 未定 | 必须与 IP / 时区同国 |

### 号码是唯一的一票否决项

`unsupported_phone_number_geo` 是**零历史硬规则**：不看行为、不累积、不看 IP，命中即拒。

`RegionSupport` 两个布尔决定走哪条路 `[服务端]`：

```java
l("claudeai_supported", true);
l("phone_verification_supported", true);
```

| `phone_verification_supported` | 注册路径 | 号码是否会成为一票否决 |
|---|---|---|
| `false` | 邮箱验证即可，Outlook 够用 | 不会 |
| `true` | **必须手机验证** | 会 |

**注册时才知道是哪种。** 准备策略：先备好一个归属国与目标地区一致的号码，否则可能全部作废。

### 支付同理

```
Google Play  → BillingConfig.countryCode
Apple IAP    → StoreKit storefront（绑定 Apple ID 区域）
Web 直付     → 卡 BIN 国家
```

换厂商不等于消除。**不要出现"美国 IP + 中国卡"。**

---

## Gate 6　安装纪律

| 项 | 要求 | 原因 |
|---|---|---|
| 只装桌面客户端 | ✅ | Android 是信号面最差的平台（`carrier_name` + Play 国家 + 号码 geo） |
| **不要手动重置 `ant-did`** | ✅ | 清理后装新版会**自动生成全新**的；手动改反而制造 churn 模式 |
| 不装反指纹浏览器 | ✅ | 必然留下矛盾组合，比原生更显眼 |
| 不装改 UA 插件 | ✅ | 只改 1 项，余下 8 项矛盾 |
| 不注册系统级 VPN（Mac） | ✅ | `scutil --nc list` / `utun*` 会被探测 |
| Windows / Mac 各自原生自洽 | ✅ | 不要把两台互相伪装成同一台 |

---

## Gate 7　注册后 72 小时

| 项 | 要求 |
|---|---|
| 首日强度 | 不要撞限额；先少量正常对话 |
| 提示词风格 | 不要复用旧账号的写法与句式 |
| 双机切换 | Windows/Mac 不要在短时间内密集交替登录 |
| 观察指标 | **新号能撑多久 = 评分累积的时间尺度** |

**诊断价值**：若新号数天内再次被处理 → 说明落在评分层（第②层），且关联锚点不在设备；若当场被拒 → 硬规则（号码或地区）。

---

## 最终自洽性验收

整套的核心不是"独特"，而是"自洽"：

| 检查 | 要求 |
|---|---|
| IP 国 = 时区国 = locale 国 = 号码国 = 支付国 | 五项必须一致 |
| 硬件 | **不变是正常的**，不要改（低熵、不承担身份） |
| `ant-did` | 全新生成即可，不要干预 |
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
