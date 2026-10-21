# Claude 客户端地区检测与封禁机制逆向分析

**分析方法**：纯静态逆向 —— Electron ASAR 解包、Bun 单文件字符串还原、APK 分包反编译（jadx）、原生模块 `otool` 符号检查。不做运行、注入、抓包或设备侧验证。

**证据分级**

| 标记 | 含义 |
|---|---|
| **[观测]** | 代码 / 资源 / 二进制里直接读到，附源码 |
| **[推断]** | 基于观测对服务端行为的合理外推，样本内无实现 |
| **[不可判定]** | 纯静态无法确定，不用推测填补 |

**样本**

| # | 文件 | 身份 |
|---|---|---|
| 1 | `Claude-offline-darwin-arm64-3.1623.0_副本.dmg` | Claude Desktop 3.1623.0 / macOS arm64 |
| 2 | `Claude-offline-win32-x64-3.1623.0.msix_副本` | 同版本 Windows MSIX |
| 3 | `claude_副本` | Claude Code CLI 2.1.306 |
| 4 | `Claude-1.261019.20-20261021_副本.zip` | Claude Android `com.anthropic.claude` 1.261019.20（Play Store 分包） |

---

## 目录

- [第一部分　总结论](#第一部分总结论)
- [第二部分　桌面端](#第二部分桌面端macos--windows)
- [第三部分　CLI](#第三部分cli-claude-code-21306)
- [第四部分　Android](#第四部分android-comanthropicclaude-126101920)
- [第五部分　综合分析](#第五部分综合分析)
- [附录](#附录)

---

# 第一部分　总结论

## 1. 一句话结论

**地区判定与封禁全部在服务端。** 三端客户端里没有任何国家白名单、制裁名单或封号决策代码；它们做的是两件事：

1. **采集并上报 VPN 改不动的信号**（系统时区、语言、设备标识、硬件画像、SIM 运营商、Play 账户国家、手机号归属地、设备密钥证明）；
2. **把服务端返回的拒绝码映射成 UI**，并对部分可恢复项做自动补救（重登记设备、重建请求、静默换模型）。

## 2. 四层拒绝模型 [观测]

源码里能读出的是**四个彼此独立、互不替代**的拒绝层：

| 层 | 判定位置 | 代表拒绝码 | 换 VPN 有效？ | 换设备有效？ |
|---|---|---|---|---|
| **① 网络边缘** | CDN / WAF | `region_unavailable`、Cloudflare challenge | ✅ 可绕过入口 | — |
| **② 地区** | 服务端 | `region_missing`、`signups_disabled_in_region`、`unsupported_phone_number_geo`、`restricted_regime_endpoint` | ❌ | ❌ |
| **③ 设备** | 服务端设备登记表 | `missing_client_attestation`、`device_check_unavailable`、`bind_attestation_*`、`untrusted_device` | ❌ | ⚠️ 换密钥=换一行，但撞配额 |
| **④ 账号** | 服务端账号状态 | `account_banned`、`account_needs_verification`、`account_on_hold`、`organization_disabled` | ❌ | ❌ |

**关键推论**：VPN 只作用于 ①。②③④ 全部与 IP 无关，这就是"挂了 VPN 还是被封"的结构性原因。

## 3. 信号可靠性排序 [观测]

| 序 | 信号 | 采集点 | VPN 可影响 |
|---|---|---|---|
| 1 | IANA 系统时区 | Desktop 注入 prompt / CLI prompt / Android RUM | ❌ |
| 2 | 持久设备标识 | `ant-did` / `machineID` / `userID` / 设备密钥 | ❌ |
| 3 | 系统语言 / locale | `getPreferredSystemLanguages()` / `Intl` / RUM | ❌ |
| 4 | Play 账户国家 | Android `BillingConfig.countryCode` | ❌ |
| 5 | 手机号归属地 | Android `unsupported_phone_number_geo` | ❌ |
| 6 | SIM 运营商 | Android RUM `carrier_name` / `cellular` | ❌ |
| 7 | 设备密钥证明 | 三端 `bind_attestation` / `reattest` | ❌ |
| 8 | 硬件 / OS 画像 | `cpu_model` / `os_build` / `device_class` | ❌ |
| 9 | 本地 VPN 接口 | macOS `utun*` / `scutil --nc list` | ⚠️ 反被识别 |
| 10 | 出口 IP / ASN | 服务端 | ✅ 唯一可控项 |

---

# 第二部分　桌面端（macOS / Windows）

## 4. 样本身份 [观测]

| 项 | 证据 |
|---|---|
| Bundle ID | `com.anthropic.claudefordesktop` |
| 版本 | 3.1623.0 |
| 结构 | Electron + `.vite` 构建，主逻辑在 `.vite/build/index.chunk-*.js` |
| Windows 同源 | `app/resources/app.asar` 与 macOS 版 JS 基本一致 |
| 原生模块 | `@ant/claude-native`、`@ant/claude-swift` |

## 5. 信号一：系统时区注入 prompt [观测]

**① `<env>` 模板**（`index.chunk-BfOAx4v9.js`）

```text
<env>
Today's date: {{currentDateTime}} (for more granularity, use bash)
Timezone: {{currentTimezone}}
Model: {{modelName}}
User name: {{accountName}}
User selected a folder: {{folderSelected}}
</env>
{{modelIdentity}}
```

模板末尾还有 `{{modelIdentity}}`（`index.chunk-BfOAx4v9.js @2450854`）。

**另有第二个 `<env>` 模板**，用于 CLI 管道输入路径（`index.chunk-oZ3hATSw.js @101409`），只含日期、不含时区：

```js
`</application_details>\n\n<env>\nToday's date: ${(new Date).toISOString().slice(0,10)}\n</env>`
```

即：**Code / Cowork 会话**走含时区的模板；**管道输入**走只含日期的模板。

**② 填充实现**（`index.chunk-DuQJhuk4.js`）

```js
M = M.replaceAll("{{currentDateTime}}", () => je());
let Me = Intl.DateTimeFormat().resolvedOptions().timeZone;
M = M.replaceAll("{{currentTimezone}}", () => Me);
```

**③ 子进程 / 沙箱环境变量**

```js
env: { TZ: Intl.DateTimeFormat().resolvedOptions().timeZone }   // VM bash
TZ: Intl.DateTimeFormat().resolvedOptions().timeZone            // Claude Code 子进程
```

> 每一次 Code / Cowork 会话，系统提示词里都带本机 IANA 时区，直接进入 Anthropic 服务端与模型上下文。

## 6. 信号二：持久设备标识 `ant-did` [观测]

文件名常量 `XBe = "ant-did"`，读写函数 `KVt()`，对外暴露 `qv()`。

```js
// 行为要点（minified，符号为实测标识）
KVt()  → resolve(app.getPath("userData"), XBe)   // 落盘位置
       → randomUUID()                            // 首次生成
       → 写入 base64 编码的 UUID（mode 0o600，flag "wx"）
qv()   → 统一读取入口（带记忆化：zVt ??= KVt()）
```

**完整实现**（`index.chunk-BfOAx4v9.js @2045945`）：

```js
function KVt(){
  try {
    let e = n.default.resolve(a.app.getPath("userData"), XBe);   // XBe = "ant-did"
    try {
      let t = WVt(e);                       // base64 解码 + UUID 正则校验
      if (t !== void 0) return t;           // 有效 → 直接复用
      let n = o.default.lstatSync(e);
      if (!n.isFile() || n.nlink > 1) throw Error("ant-did is not a plain file");
      o.default.rmSync(e);                  // 普通文件但内容无效 → 删除
    } catch (e) { if (e?.code !== "ENOENT") throw e }
    let t = (0, f.randomUUID)();
    try { GVt(e, t); }                      // writeFileSync + base64 + mode 384
    catch (t) {
      if (t?.code === "EEXIST") { let t = WVt(e); if (t !== void 0) return t }
      throw t;
    }
    return t;
  } catch (e) {
    BVt = !1;
    return N.error("Failed to read or write install file", e), (0, f.randomUUID)();
  }
}
```

三种行为：

| 情形 | 结果 |
|---|---|
| 内容有效 | 直接复用 |
| 普通文件但内容无效（`nlink === 1`） | **删除后重建** |
| 非普通文件，或 `nlink > 1` | 抛 `"ant-did is not a plain file"` → 走外层兜底 |

**外层兜底值得注意**：读写失败时返回一个**不落盘的临时 UUID** 并置 `BVt = false`。它每次启动都会变，表现为“设备标识不稳定”。

**三处使用点：**

```js
// ① GrowthBook 拉配置
"anthropic-device-id": Ist(qv())

// ② OAuth authorize
"anthropic-device-id": ...   +  "anthropic-client-platform": "DESKTOP_APP"

// ③ 遥测 envelope
install_id: qv()
```

## 7. 信号三：遥测 envelope 设备画像 [观测]

`index.chunk-BfOAx4v9.js` 的 `jAn()` 构造 `/api/event_logging/v2/batch` 元数据：

```text
product_surface:      "claude-desktop"      ← 硬编码
desktop_variant:      "production"          ← 硬编码
deployment_mode:      G().type
config_source:        d.type
config_source_remote: d.remote
app_version:          l.version
commit_hash:          l.commitHash
platform:             process.platform
arch:                 process.arch
installer_variant:    Mfe()   → "msix" | "squirrel"
store_build:          false                ← 硬编码为 false
running_under_translation: app.runningUnderARM64Translation
os_version:           process.getSystemVersion()
os_release:           os.release()
os_build:             bO()
cpu_model:            os.cpus()[0].model
total_memory:         totalKb * 1024
device_class:         NVt   ← 由 totalmem 派生
free_memory:          freeKb * 1024
available_memory:     availableKb * 1024
system_commit_limit_bytes:      commitLimitKb * 1024
system_commit_available_bytes:  commitAvailableKb * 1024
process_main_footprint_bytes / process_renderer_footprint_sum_bytes
process_renderer_main_view_heap_*
app_session_id, install_id: qv(), app_uptime_seconds, window_count
organization_id, hipaa_origin_organization_id
```

事件体（`jAn()` 内联构造）：

```js
h = {
  event_type: "TelemetryEvent",
  event_data: {
    event_name: e,
    timestamp: new Date(c).toISOString(),
    user_properties: { user_id: i || "anonymous" },
    metadata: $kn(m),
    ...(r || i) ? { auth: {
      ...(r && { organization_uuid: r }),
      ...(i && { account_uuid: i })
    } } : {}
  }
}
```

### 各字段的实际来源

| 字段 | 取值函数 | 实现 |
|---|---|---|
| `installer_variant` | `Mfe()` | `return $r() ? "msix" : "squirrel"` —— **只有两个值** |
| `os_build` | `bO()` | darwin: 读 `/System/Library/CoreServices/SystemVersion.plist` 的 `ProductBuildVersion`；win32: 读注册表 `HKLM\<…>` 的 `BuildLabEx`；失败 → `"unknown"` |
| `cpu_model` | `VEn()` | `os.cpus()[0]?.model ?? null` |
| `device_class` | `NVt` | `MVt(os.totalmem())` —— 由总内存派生 |
| `running_under_translation` | Electron | `app.runningUnderARM64Translation` |

`os_build` 在 macOS 上就是 **`ProductBuildVersion`**（形如 `24A335`），与 `os_version`（形如 `15.1`）是两个维度。

## 8. 信号四：系统语言 / locale [观测]

`index.chunk-BfOAx4v9.js` 的 `Xgt()`：

```js
function Xgt(){
  let e = a.app.getPreferredSystemLanguages();
  e.length === 0 && (e = [a.app.getLocale()]);
  N.debug("Preferred languages: %o", { langs: e });
  let t = Ygt();                                    // 可用 locale 表
  for (let n of e) {
    if (t[n]) return N.debug('Found exact match "%s" in available locales', n), n;
    let e2 = n.split("-")[0];
    let r = Object.keys(t).find(k => k.startsWith(e2 + "-") && t[k]);
    if (r) return N.debug('Found prefix match "%s" for language "%s"', r, n), r;
  }
  return N.debug("Wanted %o, available was %o, giving up", e, t), qg;   // qg = "en-US"
}
```

配套还有 `app.getSystemLocale()` 与渲染侧 `Intl` / `navigator.languages`。

### 语言列表还会直接交给渲染进程 [观测]

`index.chunk-BfOAx4v9.js` 的 `NK()`

```js
var JUr = "--desktop-managed-config=";

function YUr(e){
  let t = [];
  for (let n of e){
    let e = n.split(/[.@]/, 1)[0].replace(/_/g, "-");     // en_US.UTF-8 → en-US
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

这条串进 `process.argv`，预加载脚本再桥接给页面：

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

**远端 `claude.ai` 页面可直接读取 `window.desktopPreferredLanguages` 与 `window.desktopDeviceClass`**，不需要经过系统提示词。规范化规则：去 `.`/`@` 后缀、`_`→`-`、过滤 `C`/`POSIX`、去重。

## 9. 信号五：macOS 本地 VPN 接口探测 [观测]

`index.chunk-BfOAx4v9.js`：

```js
// VPN 接口
async function I2r(){
  (await of("/sbin/ifconfig", [])).stdout
    .match(/^(utun\d+|ppp\d+|ipsec\d+|tun\d+):/gm)
}

// 已连接的 VPN 配置名
async function L2r(){
  (await of("/usr/sbin/scutil", ["--nc", "list"])).stdout
    .matchAll(/^[^\S\n]*\*\s*\(Connected\).*"([^"]+)"/gm)
}

// 互联网共享
async function R2r(){ (await of("/usr/bin/pgrep", ["-x", "bootpd"])) }

// 虚拟网桥
async function z2r(){ /* ifconfig -a 匹配 bridge\d+ | vmnet\d+ */ }
```

汇总结构：

```js
{
  vpnActive:        connectedVPNs.length > 0,
  vpnInterfaces,    connectedVPNs,
  bootpdRunning,    bridgeInterfaces
}
```

上报位置 —— `lam_vm_startup_failed` 遥测事件：

```text
error_type: vpnActive && ... ? "vpn_routing_conflict" : <原错误>
vpn_active, vpn_interfaces, connected_vpns,
bootpd_running, bridge_interfaces,
console_tail, kernel_console_tail, service_log_tail, diagnostic_error
```

诊断函数 `B2r()` 另跑 `scutil --nwi`、`kextstat -b com.apple.vmnet`、`log show --predicate "process == 'bootpd'"`。

**边界 [观测]**

- 触发条件是 **VM 启动失败**，日志文案为「Your network traffic may be routing through a VPN, which can interfere with Claude's workspace」，用途是排障；
- Windows MSIX 同名函数（`V6r`/`I6r`/`L6r`…）是**死代码**：`if(process.platform!=="darwin") return {vpnActive:false,...}` 直接早退；
- CLI 无此逻辑（`vpnActive` / `vpn_interfaces` 命中 0）。

## 10. 信号六：每请求指纹头 [观测]

`Kv()` —— GrowthBook 每次拉配置都带：

```js
var FVt = "desktop_app", IVt = "com.anthropic.claudefordesktop";
var PVt = Math.round(os.totalmem() / 1024 ** 3);

function Kv(){
  return {
    "anthropic-client-platform":        FVt,               // "desktop_app"
    "anthropic-client-app":             IVt,               // "com.anthropic.claudefordesktop"
    "anthropic-client-version":         a.app.getVersion(),
    "anthropic-client-device-class":    <由 totalmem 派生>,
    "anthropic-client-total-memory-gb": String(PVt),
    "anthropic-client-os-platform":     process.platform,
    "anthropic-client-os-version":      process.getSystemVersion(),
    "anthropic-device-id":              Ist(qv())
  };
}
```

`Ist()` 是净化函数，不是编码器：

```js
function Ist(e){
  if (e.length === 0) return e;
  let t = e.replace(/[^\x20-\x7E]/g, "").trim();
  return t.length > 0 ? t : "invalid";
}
```

### 全部 8 个 `anthropic-client-*` 头 `[观测]`

```
anthropic-client-app
anthropic-client-device-class
anthropic-client-feature
anthropic-client-os-platform
anthropic-client-os-version
anthropic-client-platform
anthropic-client-total-memory-gb
anthropic-client-version
```

### 客户端平台枚举 `[观测]`

`index.chunk-BfOAx4v9.js @1497139`

```js
var Fst = function(e){
  return e.UNKNOWN   = "unknown",
         e.ANDROID   = "android",
         e.IOS       = "ios",
         e.DESKTOP_APP = "desktop_app",
         e.WEB_CLAUDE_AI = "web_claude_ai",
         e.WEB_CONSOLE   = "web_console",
         e.WEB_CUSTOM_AGENTS = "web_custom_agents",
         e.WEB_TRUST_PORTAL  = "web_trust_portal",
         e.WEB_ADMIN  = "web_admin",
         e.WEB_AUTH   = "web_auth", e;
}({});
```

### `anthropic-device-id` 的两处使用 `[观测]`

```js
// ① GrowthBook 拉配置
n = await a.net.fetch(t, {
  headers: VVt() ? { ...r, "anthropic-device-id": Ist(qv()) } : r,
  signal: AbortSignal.timeout(kHt)
});

// ② OAuth authorize
f = await eTn(`${e.apiHost}/v1/oauth/${o}/authorize`, {
  method: "POST",
  headers: {
    "anthropic-version": "2023-06-01",
    Authorization: `Bearer ${s}`,
    "Content-Type": "application/json",
    "anthropic-client-platform": Fst.DESKTOP_APP,
    "anthropic-client-version": a.app.getVersion(),
    ...c ? { "anthropic-device-id": Ist(c) } : {}
  },
  body: JSON.stringify({
    response_type: "code", client_id: e.clientId,
    organization_uuid: o, redirect_uri: e.redirectUri,
    scope: n ? WO(e) : e.scope, state: d,
    code_challenge: u, code_challenge_method: "S256"
  })
});
```

第三处是遥测里的 `install_id: qv()`（同源同值，非请求头）。

CLI 侧对应：`anthropic-client-platform`、`anthropic-client-version`、`anthropic-client-feature`、`anthropic-client-request-reason`、`x-organization-uuid`。

## 11. 错误码映射 [观测]

`extract/mac/asar/.vite/build/index.chunk-DWOgY7DF.js @4866`

```js
function ye({ code: e, body: n }){
  let r = t.W2;
  switch (e){
    case "org_mismatch":
      return t.d(), { errorCode: r.OrgMismatch };                 // ORG_MISMATCH
    case "tenant_restriction_violation":
    case "ip_not_in_allowed_range":
      return { errorCode: r.PolicyBlocked };                      // POLICY_BLOCKED
    case "account_banned":
      return { errorCode: r.AccountBanned };                      // ACCOUNT_BANNED
    case "account_needs_verification":
      return { errorCode: r.NeedsVerification };                  // ACCOUNT_NEEDS_VERIFICATION
    case "feature_off":
      return { errorCode: r.OrgDisabled };                        // ORG_EXPORT_DISABLED
    case "not_chat_org":
    case "cmek_blocked":
      return { errorCode: r.OrgBlocked };                         // ORG_EXPORT_BLOCKED
    case "feature_unregistered":
    case "not_a_member":
      return { errorCode: r.TemporarilyUnavailable };             // TEMPORARILY_UNAVAILABLE
    case "user_mismatch_email":
    case "invalid_email_format":
    case "user_mismatch_scim":
      return t.d(), { errorCode: r.UserMismatch };                // USER_MISMATCH
    case void 0:
      return n.includes("account_needs_verification") ? { errorCode: r.NeedsVerification }
           : n.includes("disabled for your organization") ? { errorCode: r.OrgDisabled }
           : n.includes("not available for this organization") ? { errorCode: r.OrgBlocked }
           : n.includes("Organization mismatch") ? (t.d(), { errorCode: r.OrgMismatch })
           : n.includes("user_mismatch") ? (t.d(), { errorCode: r.UserMismatch })
           : {};
    default: return {};
  }
}
```

### 映射表

| 服务端 `code` | 客户端状态 |
|---|---|
| `org_mismatch` | `ORG_MISMATCH` |
| `tenant_restriction_violation` / `ip_not_in_allowed_range` | `POLICY_BLOCKED` |
| `account_banned` | `ACCOUNT_BANNED` |
| `account_needs_verification` | `ACCOUNT_NEEDS_VERIFICATION` |
| `feature_off` | `ORG_EXPORT_DISABLED` |
| `not_chat_org` / `cmek_blocked` | `ORG_EXPORT_BLOCKED` |
| `feature_unregistered` / `not_a_member` | `TEMPORARILY_UNAVAILABLE` |
| `user_mismatch_email` / `invalid_email_format` / `user_mismatch_scim` | `USER_MISMATCH` |

枚举字面值 `[观测]`：`OrgMismatch="ORG_MISMATCH"`、`PolicyBlocked="POLICY_BLOCKED"`、`AccountBanned="ACCOUNT_BANNED"`、`NeedsVerification="ACCOUNT_NEEDS_VERIFICATION"`、`OrgDisabled="ORG_EXPORT_DISABLED"`、`OrgBlocked="ORG_EXPORT_BLOCKED"`、`TemporarilyUnavailable="TEMPORARILY_UNAVAILABLE"`、`UserMismatch="USER_MISMATCH"`。

### 上下文：这是导出/导入任务的映射

状态值本身说明了作用域 —— `ORG_EXPORT_DISABLED` / `ORG_EXPORT_BLOCKED` 都带 **EXPORT**。`ye()` 属于 claude-ai 数据导出/导入流程，同文件内还有三个导出专用态：

```js
case "export_expired":        return { errorCode: a.ExportExpired,  dropPending: !0 };
case "export_consumed":
case "export_link_used":      return { errorCode: a.ExportConsumed, dropPending: !0 };
case "feature_off":           return { errorCode: a.OrgDisabled,    dropPending: !0 };
default:
  return i && e === 410
    ? { errorCode: r.includes("expired") ? a.ExportExpired : a.ExportConsumed, dropPending: !0 }
    : { errorCode: a.NotAvailable, ...(i && { dropPending: !0 }) };
```

`POLICY_BLOCKED` 与 `ACCOUNT_BANNED` 是跨流程复用的通用态，其余为导出专用。

### body 文本兜底 `[观测]`

`case void 0`（服务端未给结构化 `code`）时改用**响应体子串匹配**：

```
"account_needs_verification"          → NeedsVerification
"disabled for your organization"      → OrgDisabled
"not available for this organization" → OrgBlocked
"Organization mismatch"               → OrgMismatch
"user_mismatch"                       → UserMismatch
```

即：**服务端即使只回一段自然语言，只要命中这几个子串，客户端依然会映射成封禁/验证态。**

> 客户端里**没有任何**"我要封你"的逻辑，只有把服务端 `code`（或其文案）映射成 UI 状态。

## 12. 遥测出口白名单 [观测]

`index.chunk-BfOAx4v9.js` 的 endpoint 策略表（节选）：

```js
"datadog-rum": {
  toggleKey: "disableEssentialTelemetry",
  label: "Essential telemetry",
  endpoints: ({ anthropicHost: e }) => [
    { host: e, path: "/api/v2/rum", exactPath: true, origin: "renderer",
      cspDirective: [], undeliveredAs503: true, purpose: ize },
    ...XCe.map(e => ({ host: e, origin: "renderer", purpose: ize }))
  ]
},
"anthropic-telemetry": {
  toggleKey: "disableNonessentialTelemetry",
  label: "Nonessential telemetry",
  endpoints: ({ anthropicHost: e }) => [
    { host: e,  path: "/api/event_logging/", origin: "renderer",   purpose: rze },
    { host: Fo, path: "/api/event_logging/", origin: "subprocess",
      purpose: "Claude Code usage telemetry" }
  ]
},
sentry: {
  toggleKey: "disableEssentialTelemetry",
  endpoints: [
    { host: zCe, origin: "renderer", purpose: tze,
      firewallAlso: ["*.ingest.us.sentry.io"] },
    { host: "sentry.io", origin: "renderer", purpose: tze }
  ]
}
```

隐私开关：`disableEssentialTelemetry`（datadog-rum / sentry）、`disableNonessentialTelemetry`（anthropic-telemetry）。

---

# 第三部分　CLI（Claude Code 2.1.306）

## 13. 样本身份 [观测]

| 项 | 证据 |
|---|---|
| Bundle ID | `com.anthropic.claude-code` |
| TeamID | `Q6L2SF6YDW` |
| 形式 | Bun 单文件，JS 以明文嵌入 `/$bunfs/root/chunk-*.js` |
| 提取方式 | `strings -a claude > /tmp/cc.txt` |
| 版本串 | `2.1.306 (Claude Code)` |

## 14. 设备密钥：ECDSA P-256 [观测]

```js
var J = { privateKeyPkcs8B64, rowPk }        // 私钥 PKCS#8 + 行标识
var C = "Claude Code-device-keys"            // 凭据库服务名
var h = Symbol("deviceKeyStore.NO_KEYCHAIN") // 无 keychain 时降级

// 降级文件路径：<configDir>/.device-keys
// 写入：withWriteLock，重试 10 次
// 曲线：prime256v1
// 签名编码："ieee-p1363"（JOSE/ECDSA 原始 r||s）
```

## 15. 设备注册与吊销 [观测]

```js
var De = "/api/organizations/:orgUUID/cowork/remote_devices";
var Ke = "cowork_remote_device_limit_reached";        // 单账号设备上限
var Se = "cowork_remote_device_registration_revoked"; // 服务端吊销
var he = "account_session_invalid";

// 注册返回 201 才算成功；以下情况直接抛错并带公钥
if (c === Se || (a.status === 403 && c === undefined))
    throw new g$e(s.publicKeySpkiB64);
if (a.data?.revoked_at !== null && a.data?.revoked_at !== undefined)
    throw new g$e(...);
```

错误文案：

```text
"this machine's device registration was removed from the account"
"device registration revoked" / "registration_revoked"
"device registration unavailable for this account or organization"
```

独立设备配对错误组（不属于 device registry，由 `GGs()` 归类）：`duplicate_device_id`、`device_name_in_use`、`device_session_limit`。

**新设备绑定：**

```text
[deviceBind] expectedCurrentDeviceUuid  newDeviceUuid  signedOver
hasDeviceProof  confirmReenroll  refusedPublicKey
tengu_device_bind_account  tengu_device_bind_skipped
tengu_device_bind_failed   tengu_device_reenroll
[deviceBind] could not forget the cached device id
```

**设备证明失败集合**（桌面端 `index.chunk-oZ3hATSw.js`，CLI 同构）：

```js
new Set([
  "untrusted_device", "session_stale_relogin", "device_key_missing",
  "bind_attestation_stale", "bind_attestation_invalid",
  "bind_attestation_missing", "bind_device_not_found"
])
```

**触发链路：**

```js
if (status === 403 && code === "untrusted_device") return "untrusted_device";
// 于是自动重新登记
let e = await this.enrollTrustedDevice();
```

**门控开关：**

```text
isTrustedDeviceGateEnabled        isTrustedDeviceRequiredOrUnknown
isTrustedDeviceUnenrolled         preflightTrustedDeviceBlocking
trusted_devices_required_or_unknown
trusted_device_required           project_session_trusted_device_org
tool_host_proof_needs_request     tool_host_proof_missing   tool_host_proof_invalid
```

## 16. `policy_limits`：服务端下发策略 [观测]

完整模块 `index.chunk-DIjipm-e.js`（2,920 字节）：

```js
const a = 3000;                    // 3s 超时
const o = "oauth-2025-04-20";      // anthropic-beta

URL("/api/claude_code/policy_limits", apiHost)
headers: Authorization: Bearer <token>
      → { restrictions: {...}, compliance_taints?: [...], defaults?: {...} }

// 403 → { ok:false, status } → 后续按 not_permitted 处理
// 落盘：<userData>/policy-limits.json，24h 过期（864e5）
// 读盘做 schema 校验
// 冷启动阻塞等待：policy_limits_cold_await / policy_limits_await_ms
```

日志字符串：

```text
Policy limits: Fetched successfully
Policy limits: Using cached restrictions (304)
Policy limits: malformed compliance_taints element(s) dropped
[policyLimits] GET … → 403
[mcp-policy-cold-start] waiting on the policy-limits verdict
    (compliance taints feed config ${VAR} expansion)
[mcp-policy-cold-start] policy-limits verdict did not land within the
    cold-start budget; loading MCP configs without it
```

> `compliance_taints` 是按合规辖区打的功能开关：命中后连配置里的 `${VAR}` 展开都会受限。这是"同一账号在不同辖区能力不同"的实现位。

## 17. 拒绝码集合 [观测]

```js
// 组织存活类
xK = new Set(["organization_on_hold", "organization_disabled"])

// 凭据吊销类（终端性）
EA = new Set(["token_revoked", "org_access_revoked",
              "workspace_revoked", "application_deactivated"])

// 策略拒绝类（终端性）
OK = new Set(["oauth_not_allowed_for_organization",
              "claude_code_key_creator_not_member",
              "restricted_regime_endpoint"])

// 网络类
MK = new Set(["ENOTFOUND","EAI_AGAIN","ECONNREFUSED","ECONNRESET",
              "EHOSTUNREACH","ENETUNREACH","EPIPE"])

// 存活判定集合
ce = ["not_permitted", "ip_restricted", "lane_unavailable"]
```

完整拒绝原因：

| 类别 | 取值 |
|---|---|
| IP / 网络边界 | `ip_restricted`、`ip_not_in_allowed_range`、`refused_ip_allowlist`、`lane_unavailable`、`not_permitted`、`blocked_by_intermediary` |
| 账号状态 | `refused_account_on_hold`、`oauth_callback_account_on_hold`、`organization_on_hold`、`organization_disabled`、`refused_not_entitled` |
| 凭据 | `refused_credential_expired`、`refused_credential_revoked`、`token_expired` / `token_revoked` / `token_invalid` / `credential_invalid`、`oauth_scope_insufficient`、`client_scope_insufficient` |
| 组织 | `oauth_not_allowed_for_organization`、`claude_code_key_creator_not_member`、`org_access_revoked`、`workspace_revoked`、`oauth_application_deactivated`、`organization_not_visible` |
| 辖区 | `restricted_regime_endpoint` |
| 设备 | `untrusted_device`、`device_key_missing`、`bind_attestation_*`、`bind_device_not_found` |

OAuth 回调页直接显示：

```text
"Your account is on hold. You can close this window."
```

## 18. 辖区（regime）限制 [观测]

```text
api_request_regime_features_refused     ← 遥测事件
api_regime_refusal_recovery             ← 恢复流程
decision_failed
nothing_to_rebuild
[regime-refusal] resending the refused request,
    rebuilt under the organization policy now loaded
```

即：服务端以辖区为由拒绝后，客户端**重建请求再发一次**（带上刚加载的组织策略），并把这次拒绝单独计数。这是除 `account_banned` 之外第二条明确以"辖区"命名的拒绝路径。

## 19. 模型级门控 [观测]

```text
model_access_refused
model_access_denied
[model-access] now using <model> as its tier's default: every newer model
    of the tier was refused, is not allowed, or was skipped because of
    its context window
tengu_api_model_not_found_fallback_triggered
    { original_model, fallback_model, reason: "model_access_refused" }
```

模型目录由服务端下发：

```text
https://downloads.claude.ai/model-catalog/v1/schema.json
/api/organizations/:orgUUID/model_selector/
/api/model_selector/
tengu_model_catalog_compare / [servedCatalog] / publishedCatalog / unsupported_schema
```

> 某些模型在某些账号 / 辖区不可用时**不报错**，而是静默回退到同档位默认模型。

## 20. 内容与合规层 [观测]

遥测事件名即规则清单：

```text
api_request_dlp_denied               ← DLP 拦截
api_request_safety_monitor_blocked   ← 安全监测拦截
api_request_output_content_filtered  ← 输出过滤
api_request_verification_required    ← 触发身份 / 年龄验证
api_request_regime_features_refused  ← 辖区功能拒绝
```

本地对应：`dlp_request_denied`、`safety_monitor_blocked`、`failClosedOnUnknownSource`、`VerificationRequiredError`。

验证入口主机白名单（`pGe()`）：`portal.anthropic.com`、`claude.ai`、`platform.claude.com`。

## 21. 组织自建网关 IP 策略 [观测]

CLI 内置 managed-settings 网关组件，自带 IP 访问控制。**真实代码**：

```js
if (hl) return Vt("access.denied", {
    reason: "xff_unparseable", client_ip: Fe, xff_hop: Pn
  }), new Response("forbidden", { status: 403 });

if (Fe === void 0 && hl) return Vt("access.denied", {
    reason: "client_ip_unknown"
  }), new Response("forbidden", { status: 403 });

if (Du(Fe, o)) return Vt("access.denied", {
    reason: "ip_denylist", client_ip: Fe
  }), new Response("forbidden", { status: 403 });
```

完整 reason 取值：

```text
xff_unparseable | client_ip_unknown | ip_denylist | ip_not_allowlisted | provider_policy
"gateway_provider_policy_refusal"
"access.public_client"    // 请求来自非私网地址 → 拒绝（防公网可达）
```

**边界**：这是**企业 / 组织**在自建网关上配的 IP 策略，不是 Anthropic 的国别策略；错误码不共享（前者 `access.denied`，后者 `ip_restricted` / `ip_not_in_allowed_range`）。不要混为一谈。

## 22. 连通性预检 [观测]

```js
t = [`${BASE_API_URL}/api/hello`, `${TOKEN_URL.origin}/v1/oauth/hello`]
// 非 200 → { success: false, error: `Failed to connect to ${host}: Status ${status}` }
```

失败 UI（onboarding preflight）：

```jsx
e(n, { children: "Please check your internet connection and network settings." }),
r(n, { children: [
  "Note: Claude Code might not be available in your country.",
  " Check supported countries at", " ",
  e(n, { color: "suggestion", children: "https://anthropic.com/supported-countries" })
]})
```

> 地区阻断由服务端在这些端点返回非 200 实现，客户端只给提示。

---

# 第四部分　Android（`com.anthropic.claude` 1.261019.20）

> 本部分**仅做静态分析**：只读分包 APK、`classes*.dex`、`resources.arsc` 解码结果与 jadx 反编译源码。

## 23. 样本身份 [观测]

| 项 | 值 |
|---|---|
| Package | `com.anthropic.claude` |
| Version | `1.261019.20`（`versionCode 26101920`） |
| 结构 | `base.apk` + `split_config.arm64_v8a` + `split_config.xxxhdpi` + `split_config.zh` |
| 签名 | APK Signature Scheme v2（`APK Sig Block 42` @ offset 44330992） |
| 来源设备 | `<DEVICE_SERIAL> (<DEVICE_MODEL>)`，`adb install-multiple` |
| compileSdk | 37 |
| 反编译规模 | 40,106 个 `.java`（jadx），`defpackage/` 占 38,001 |

**四个分包 SHA-256**

```text
base                    311e43e1138138888a4fd3d3cfbc1edb015eaa444731414855dd059290c7ab8f
split_config.arm64_v8a  2a7c65a2606191f150f82c94d1ee9b2f191d2f7898f427f1354c56b8207c8da9
split_config.xxxhdpi    7ad20e0abde7d112b766c6fe6aa0bc4784a43d64390aeb8839a5c1d31bbc1ac0
split_config.zh         e544b007ecba91b20c5ab859fa628297d9e3d83fca72bd6ef8a9012b0ae21009
```

**manifest 关键权限**（与桌面端 / CLI 的差异）

```xml
ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION      <!-- 桌面端没有 -->
RECORD_AUDIO
READ_CALENDAR / WRITE_CALENDAR
DETECT_SCREEN_CAPTURE
android.permission.health.READ_*   (约 40 个)
com.android.vending.BILLING
com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE
```

## 24. 核心发现：地区判定是一次显式服务端查询 `RegionSupport` [观测]

`extract/apk2/jadx/sources/defpackage/y9t.java`：

```java
package defpackage;

import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;

/* JADX INFO: loaded from: classes3.dex */
public final /* synthetic */ class y9t implements eqg {
    public static final y9t a;
    private static final SerialDescriptor descriptor;

    static {
        y9t y9tVar = new y9t();
        a = y9tVar;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor =
            new PluginGeneratedSerialDescriptor(
                "com.anthropic.claude.api.verification.RegionSupport", y9tVar, 2);
        pluginGeneratedSerialDescriptor.l("claudeai_supported", true);
        pluginGeneratedSerialDescriptor.l("phone_verification_supported", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    @Override // defpackage.eqg
    public final KSerializer[] childSerializers() {
        wl4 wl4Var = wl4.a;
        return new KSerializer[]{wl4Var, wl4Var};
    }
    // ...
}
```

**同包内配套类**

```text
com.anthropic.claude.api.verification.RegionSupport
com.anthropic.claude.api.verification.SendPhoneVerificationCodeRequest
com.anthropic.claude.api.verification.SendPhoneVerificationCodeResponse
com.anthropic.claude.api.verification.VerifyPhoneVerificationCodeRequest
```

`SendPhoneVerificationCodeRequest` 字段表 —— `defpackage/j5w.java`：

```java
static {
    j5w j5wVar = new j5w();
    a = j5wVar;
    PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor =
        new PluginGeneratedSerialDescriptor(
            "com.anthropic.claude.api.verification.SendPhoneVerificationCodeRequest",
            j5wVar, 2);
    pluginGeneratedSerialDescriptor.l("phone_number", false);
    pluginGeneratedSerialDescriptor.l("client_attestation", true);
    descriptor = pluginGeneratedSerialDescriptor;
}

@Override
public final KSerializer[] childSerializers() {
    return new KSerializer[]{bdz.a, fm40.H(ze8.a)};
}
```

**结论**：客户端上报 `phone_number` + `client_attestation`，服务端返回 `RegionSupport{claudeai_supported, phone_verification_supported}` 或返回拒绝码。"这个地区能不能用"不是客户端算的。

**[推断]** 两个布尔分开 ⇒ 存在"能用 Claude 但该地区不做手机验证"的中间态，这类地区大概率走邮箱登录。

## 25. 拒绝码枚举（Android 词表）[观测]

### 25.1 注册 / 登录 / 账号闸 —— `defpackage/j08.java`

```java
public final class j08 {
    DEFAULT_UNKNOWN_ERROR("default_unknown_error"),
    SIGNUPS_DISABLED("signups_disabled"),
    REGION_MISSING("region_missing"),
    SIGNUPS_DISABLED_IN_REGION("signups_disabled_in_region"),
    SIGNIN_TEMPORARILY_DISABLED("signin_temporarily_disabled"),
    NO_CONSOLE_ACCOUNT("no_console_account"),
    INVALID_RECAPTCHA("invalid_recaptcha"),
    ACCOUNT_NEEDS_VERIFICATION("account_needs_verification"),
    ACCOUNT_BANNED("account_banned"),
    INVALID_AUTHORIZATION("Invalid authorization"),
    ACCOUNT_SESSION_INVALID("account_session_invalid"),
    EMAIL_AUTH_DISABLED("email_auth_disabled"),
    SIGN_IN_NOT_PERMITTED("sign_in_not_permitted"),
    MFA_CHALLENGE_SENDS_EXHAUSTED("mfa_challenge_sends_exhausted");

    public static final LinkedHashMap v;
    public final String u;

    static {
        uqe uqeVar = new uqe(j08VarArr);
        int iA0 = erl.a0(qr9.K0(uqeVar, 10));
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA0 < 16 ? 16 : iA0);
        Iterator it = uqeVar.iterator();
        while (true) {
            o1 o1Var = (o1) it;
            if (!o1Var.hasNext()) { v = linkedHashMap; return; }
            Object next = o1Var.next();
            linkedHashMap.put(((j08) next).u, next);
        }
    }
}
```

> 注意：jadx 对该枚举标注了 `Enum visitor error` / `Fake field`，**常量名可能被重排**，但 `values()` 数组里的**字符串值是权威的**。下表以字符串值为准。

| 字符串值 | 含义 |
|---|---|
| `region_missing` | 地区判定不出来 |
| `signups_disabled` | 全局关闭注册 |
| `signups_disabled_in_region` | **该地区禁止注册** |
| `signin_temporarily_disabled` | 登录临时关闭 |
| `sign_in_not_permitted` | 不允许登录 |
| `email_auth_disabled` | 邮箱登录关闭 |
| `no_console_account` | 无 Console 账号 |
| `account_banned` | 账号封禁 |
| `account_needs_verification` | 需二次验证 |
| `account_session_invalid` | 会话失效 |
| `Invalid authorization` | 授权无效 |
| `invalid_recaptcha` | recaptcha 失败 |
| `mfa_challenge_sends_exhausted` | MFA 发送次数耗尽 |
| `default_unknown_error` | 兜底 |

### 25.2 手机号 / 验证闸 —— `defpackage/m08.java`

```java
public final class m08 {
    DEFAULT_UNKNOWN_ERROR("default_unknown_error"),
    MAGIC_LINK_INVALID("invalid_phone_number"),               // 常量名被重排
    UNSUPPORTED_PHONE_NUMBER_GEO("unsupported_phone_number_geo"),
    PHONE_NUMBER_TEMP_BLOCKED("phone_number_temp_blocked"),
    EXPIRED_VERIFICATION("expired_verification"),
    VERIFICATION_FAILED("verification_failed"),
    MFA_CHALLENGE_INVALID("mfa_challenge_invalid"),
    ALREADY_USED("already_used"),
    ALREADY_VERIFIED("already_verified"),
    MUST_UPGRADE("must_upgrade"),
    // ...
}
```

**`unsupported_phone_number_geo` 是硬地缘闸**：号码归属地不支持，与 IP 无关。

### 25.3 设备证明闸

```text
missing_client_attestation  / MISSING_CLIENT_ATTESTATION
device_check_unavailable
trusted_device_attestation_failed
```

### 25.4 边缘闸（进不到应用逻辑）

dex 字符串：

```text
"refused at the network edge: region unavailable"
"refused at the network edge: Cloudflare challenge (HTTP %d)"
```

独立异常类型：

```text
ClaudeApiError$CloudflareChallengeError
ClaudeApiError$CloudflareWaitingRoomError
region_unavailable
```

> `region unavailable` 在边缘返回 ⇒ 国家级拦截放在 CDN / WAF 层（Cloudflare），不靠应用层逐请求判定。

## 26. VPN 改不动的硬信号

### 26.1 Google Play 账户国家 [观测]

`defpackage/l4j.java` case 18：

```java
case 18:
    npb npbVar18 = npb.u;
    boolean z18 = this.z;
    try {
        if (!z18) {
            lbj.Q(obj);
            l6h l6hVar = (l6h) this.A;
            this.z = true;
            if (l6hVar.b(this) == npbVar18) return npbVar18;
        } else {
            if (!z18) { gp.o("call to 'resume' before 'invoke' with coroutine"); return null; }
            lbj.Q(obj);
        }
        break;
    } catch (CancellationException e2) {
        throw e2;
    } catch (Throwable th2) {
        SilentException.a(new SilentException(
            "Play Store country lookup failed: ".concat(lbj.e(th2))), null, null, 7);
    }
    return v720.a;
```

配套证据：dex 含 `IInAppBillingGetBillingConfigCallback`、`Play Billing rc=`。

**这是 Google 账号绑定的 Play 商店国家（`BillingConfig.countryCode`），由 Google 侧维护，与 IP 无关。**

### 26.2 手机号归属地

见 25.2 `unsupported_phone_number_geo`。

### 26.3 设备密钥 + 会话级 reattest [观测]

**端点与协议**

```text
api/auth/session_reattest/device_key
api/auth/session_reattest/device_key/challenge
anthropic.reattest.v1
anthropic.reattest_rotate.v1
type.googleapis.com/anthropic.bard.api.v1alpha.BindDevice.Attestation
```

**类型**

```text
ReattestChallengeResponse   ReattestVerifyRequest
RotateReattestRequest       RotateReattestResponse
ReattestPromptResult        DeviceAttestation     AttestationFeedback
```

**字段 / 标志**

```text
attestation_blob       attestation_nonce      attestation_issued_at
attestation_kid_missing  new_reattest_public_key  reattest_kid
canReattest   markNeedsReenrollForAttestation   NEEDS_REENROLL_ATTESTATION
ClientEventAttestation sign failed
trusted_device_attestation_failed   trusted_device_reattest
```

**登出清理器** `defpackage/r8.java`（`AccountLogoutCleaner`，方法体被 jadx 跳过但字符串完整）：

```java
try {
    ((yzx) this.D).d(xelVar);
} catch (Exception e) {
    if (e instanceof CancellationException) throw e;
    h5g.v("AccountLogoutCleaner.signOutTextRequested", e, cexVar, null, 6);
}
for (tzx tzxVar : this.E) {
    try {
        ((icq) tzxVar).c(this.d, xelVar);
    } catch (Exception e2) {
        if (e2 instanceof CancellationException) throw e2;
        h5g.v("AccountLogoutCleaner.signOutRequested", e2, cexVar2, null, 6);
    }
}
```

清理项：`legacyTrustedDeviceKeys`、`legacyTrustedDeviceRow`、`integrity`、`ageSignals`、`cookieJar`、`knownAccount`、`filesDirs`、`externalTmpDir`、`hubDebugConfig`、`allNotifications`。

中断恢复语义：

```text
"AccountLogoutCleaner: an earlier sign-out of this account was cut off before
 it ended; this sign-out finishes it"
"AccountLogoutCleaner: keeping the account's settings for its next sign-in (reason: …)"
"AccountStorageCleaner: wiped account storage"
```

### 26.4 SIM 运营商 [观测]

Datadog RUM 设备上下文 schema 中的键：

```text
brand  architecture  locale  locales  time_zone
power_saving_mode  brightness_level  logical_cpu_count  total_ram  is_low_ram
carrier_name  cellular
```

桌面端**没有** `carrier_name` / `cellular`。

## 27. 登录期 attestation：静态确认成立 [观测]

`defpackage/py20.java` —— `com.anthropic.claude.api.login.VerifyGoogleRequest`，**5 个字段**：

```java
static {
    py20 py20Var = new py20();
    a = py20Var;
    PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor =
        new PluginGeneratedSerialDescriptor(
            "com.anthropic.claude.api.login.VerifyGoogleRequest", py20Var, 5);
    pluginGeneratedSerialDescriptor.l("code", false);
    pluginGeneratedSerialDescriptor.l("redirect_uri", false);
    pluginGeneratedSerialDescriptor.l("play_integrity_token", false);
    pluginGeneratedSerialDescriptor.l("client_attestation", true);
    pluginGeneratedSerialDescriptor.l("source", true);
    descriptor = pluginGeneratedSerialDescriptor;
}

@Override
public final KSerializer[] childSerializers() {
    bdz bdzVar = bdz.a;
    return new KSerializer[]{
        bdzVar, bdzVar, fm40.H(bdzVar), fm40.H(ze8.a), bdzVar
    };
}
```

**结论：`play_integrity_token` 与 `client_attestation` 会随 Google 登录校验一起发出，不只用于购买。**

**邮箱路径** —— `defpackage/h3w.java`：

```java
public final Object a(u3w u3wVar, pn20 pn20Var, xva xvaVar) {
    // ...
    jG = this.c.g() / 1000;                       // 时间戳（秒）
    ab3.f.getClass();
    String strB = ab3.b(ab3.h.d(2), this.d.a().a());   // challenge
    if (this.b.k("claudeai_send_email_attestation")) {
        String strR = ua50.r(jG, strB, u3wVar.b());    // 签名载荷
        pn20Var.a();
        t1s t1sVar = new t1s(this, strR, af8VarN, (byte) 5);
        f3wVar.x = u3wVar;
        f3wVar.y = strB;
        f3wVar.z = jG;
        f3wVar.C = 1;
        Object objB = b(t1sVar, f3wVar);
        Object obj2 = npb.u;
        if (objB == obj2) return obj2;
        // ...
    }
    // ...
    return new ni2(u3w.a(u3wVar, l, str, af8VarN), ez00Var);
}
```

对应状态机 —— `defpackage/hu30.java`：

```java
public final void P(bld bldVar, boolean z) {
    long jE = this.A.e();
    Long lC = bldVar.c();
    ez00 ez00VarB = bldVar.b();
    boolean z2 = lC != null
              || (!bldVar.e() && this.D.b.i("claudeai_send_email_attestation"));
    if (ez00VarB != null) {
        strP = na50.p(ez00VarB);
    } else {
        strP = z2 ? "pending" : "not_asked";
    }
    // ...
}
```

即**发登录邮件前**就要一份证明：未拿到 → `pending`；flag 关闭 → `not_asked`。

## 28. Play Integrity：只服务支付，且明确 fail-open [观测]

### 28.1 订阅购买 —— `defpackage/x7h.java`

```java
/* JADX WARN: Code duplicated, block: B:7:0x0015  */
public final Object x(qes qesVar, sds sdsVar, boolean z, xva xvaVar) {
    // ...
    try {
        if (i2 == 0) {
            lbj.Q(objA);
            if (sdsVar.f() || !this.e.k("claudeai_play_integrity_purchase_attestation")) {
                return qesVar;                              // flag 关 / 无需证明 → 放行
            }
            String str = "gplay-claim/v1:" + sdsVar.e();     // challenge
            u6h u6hVar = this.f;
            long j = y7h.b;
            w7hVar.x = qesVar;
            w7hVar.y = z;
            w7hVar.B = 1;
            objA = u6hVar.a(j, w7hVar, str);
            npb npbVar = npb.u;
            if (objA == npbVar) return npbVar;
        } else {
            if (i2 != 1) { gp.o("call to 'resume' before 'invoke' with coroutine"); return null; }
            z = w7hVar.y;
            qesVar = w7hVar.x;
            lbj.Q(objA);
        }
        i4n i4nVar = (i4n) objA;
        int iQ = ryf.q(i4nVar);
        if (iQ == 0) {
            wdsVar = new wds(((h4n) i4nVar).a(), (String) null, 2);
        } else {
            if (iQ != 1) throw new NoWhenBranchMatchedException();
            wdsVar = new wds((String) null, ((g4n) i4nVar).a().a(), 1);
        }
    } catch (CancellationException e) {
        throw e;
    } catch (Throwable th) {
        c700 c700Var = c700.a;
        c700.f(th, "GooglePlaySubscriptionManager: Play Integrity attestation failed;"
                 + " sending the purchase without it.", null, null, null, 60);
        wdsVar = new wds((String) null, f4n.OTHER.a(), 1);   // 无 token 也照发
    }
    return qes.a(qesVar, wdsVar, Boolean.valueOf(z));
}
```

### 28.2 额度 / credit 购买 —— `defpackage/wkq.java`

```java
public final Object b(p6h p6hVar, boolean z, xva xvaVar) throws Throwable {
    // ...
    if (i2 == 0) {
        lbj.Q(objA);
        if (!this.a.a.k("claudeai_play_integrity_credit_purchase_attestation")) {
            return p6hVar;
        }
        String str = p6hVar.a;
        vkqVar.x = p6hVar;
        vkqVar.y = z;
        vkqVar.B = 1;
        objA = a(str, vkqVar);
        Object obj = npb.u;
        if (objA == obj) return obj;
    } else {
        if (i2 != 1) { gp.o("call to 'resume' before 'invoke' with coroutine"); return null; }
        z = vkqVar.y;
        p6hVar = vkqVar.x;
        lbj.Q(objA);
    }
    Boolean boolValueOf = Boolean.valueOf(z);
    return new p6h(p6hVar.a, p6hVar.b, (wds) objA, boolValueOf);
}
```

铸造失败分支：

```java
} catch (Throwable th2) {
    iknVar3 = iknVar7;
    c700 c700Var = c700.a;
    c700.f(th2, "PlayIntegrityCreditClaimAttester: the mint threw;"
              + " sending the claim without a token.", null, null, null, 60);
    wdsVar = new wds((String) null, "other", 1);
    iknVar5 = iknVar3;
}
```

### 28.3 铸造本体 —— `defpackage/o7j.java`

```java
public final Object a(long j, xva xvaVar, String str) {
    // ...
    try {
        if (i2 == 0) {
            lbj.Q(objV);
            if (!this.a.b) {
                return new af8((String) null, f4n.UNSUPPORTED_BUILD.a(), 1);
            }
            k7j k7jVar = new k7j(this, str, vvaVar, (byte) 0);
            j7jVar.z = 1;
            objV = o4.V(j, k7jVar, j7jVar);
            npb npbVar = npb.u;
            if (objV == npbVar) return npbVar;
        } else {
            if (i2 != 1) { gp.o("call to 'resume' before 'invoke' with coroutine"); return null; }
            lbj.Q(objV);
        }
        String str2 = (String) objV;
        if (str2 != null && str2.length() != 0) {
            return new af8(str2, (String) null, 2);
        }
        f4nVar = f4n.NO_TOKEN;
    } catch (CancellationException e) {
        fpb fpbVar = j7jVar.v;
        fpbVar.getClass();
        y220.r(fpbVar);
        if (e instanceof TimeoutCancellationException) f4nVar2 = f4n.TIMEOUT;
        f4nVar = f4nVar2;
    } catch (Exception e2) {
        f4n f4nVarA = ((zkq) this.b).a(e2);
        if (f4nVarA == null) {
            SilentException.a(new SilentException(
                "Play Integrity challenge token not minted;"
              + " the request goes out without one", e2), cex.v, null, 6);
        } else {
            f4nVar2 = f4nVarA;
        }
        f4nVar = f4nVar2;
    }
    return new af8((String) null, f4nVar.a(), 1);
}
```

失败原因枚举：`UNSUPPORTED_BUILD` / `NO_TOKEN` / `TIMEOUT` / `OTHER`。

载荷字段 —— `defpackage/vds.java`（`PurchaseAttestation`）：

```text
play_integrity_token
play_integrity_mint_error
```

**[推断]** Play Integrity 是**收入保护信号**（判断内购是否来自被改过的客户端），不参与地区判定或封号判定；失败只给请求打"无 token / 不可用"标签，由服务端另行决定。

## 29. 位置权限：三态精度 + 权限获取流程 [观测]

### 29.1 枚举与结果类型

`defpackage/a2q.java`：

```java
public final class a2q {
    public static final a2q u;   // NONE        = 0
    public static final a2q v;   // APPROXIMATE = 1
    public static final a2q w;   // PRECISE     = 2

    static {
        a2q a2qVar  = new a2q("NONE", 0);        u = a2qVar;
        a2q a2qVar2 = new a2q("APPROXIMATE", 1); v = a2qVar2;
        a2q a2qVar3 = new a2q("PRECISE", 2);     w = a2qVar3;
        x = new a2q[]{ a2qVar, a2qVar2, a2qVar3 };
    }
}
```

`defpackage/b2q.java` —— 结果类型 `(精度, 布尔)`：

```java
public final class b2q {
    public final a2q a;      // 最终精度档位
    public final boolean b;  // 是否发生了"新授予"

    public b2q(a2q a2qVar, boolean z) {
        this.a = a2qVar;
        this.b = z;
    }
}
```

### 29.2 真实方法体 —— `defpackage/bi.java`（`implements c2q`）

```java
public final Object e(boolean z, xva xvaVar) {
    // ... 协程状态机样板 ...
    a2q a2qVar2 = a2q.u;                 // NONE
    Context context = this.a;
    a2q a2qVar3 = a2q.v;                 // APPROXIMATE
    a2q a2qVar4 = a2q.w;                 // PRECISE

    if (i2 == 0) {
        lbj.Q(obj);

        // ① 读当前已授予的精度档位
        if (yga.n(context, "android.permission.ACCESS_FINE_LOCATION") == 0) {
            a2qVar = a2qVar4;                       // PRECISE
        } else {
            a2qVar = yga.n(context, "android.permission.ACCESS_COARSE_LOCATION") == 0
                   ? a2qVar3                        // APPROXIMATE
                   : a2qVar2;                       // NONE
        }

        // ② 已满足需求（需要精确则比 PRECISE，否则比 APPROXIMATE）→ 不再申请
        if (a2qVar.compareTo(z ? a2qVar4 : a2qVar3) >= 0) {
            return new b2q(a2qVar, false);
        }

        // ③ 不满足 → 发起系统权限申请
        Object obj2 = npb.u;
        if (z || Build.VERSION.SDK_INT >= 31) {
            vhVar.z = 1;
            Object objG = g(new String[]{
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION"
            }, vhVar);
            if (objG != obj2) {
                obj = objG;
                zBooleanValue = ((Boolean) obj).booleanValue();
            }
        } else {
            vhVar.z = 2;
            Object objG2 = g(new String[]{
                "android.permission.ACCESS_COARSE_LOCATION"
            }, vhVar);
            if (objG2 != obj2) {
                obj = objG2;
                zBooleanValue = ((Boolean) obj).booleanValue();
            }
        }
        return obj2;
    }

    // ④ 申请返回后，重新读一次最终档位并回传
    // ...
    if (yga.n(context, "android.permission.ACCESS_FINE_LOCATION") == 0) {
        a2qVar2 = a2qVar4;
    } else if (yga.n(context, "android.permission.ACCESS_COARSE_LOCATION") == 0) {
        a2qVar2 = a2qVar3;
    }
    return new b2q(a2qVar2, zBooleanValue);
}
```

### 29.3 这段代码到底在做什么（按代码，不夸大）

| 步骤 | 行为 |
|---|---|
| ① | 用 `Context.checkPermission` 读出当前是 `PRECISE` / `APPROXIMATE` / `NONE` |
| ② | 与需求档位比较（`z = true` 要 PRECISE，否则 APPROXIMATE）；已满足则不打扰用户 |
| ③ | 不满足时发起系统权限申请：SDK ≥ 31 或要精确 → 同时申请 FINE + COARSE；否则只申请 COARSE |
| ④ | 申请返回后重新读档位，返回 `b2q(精度, 是否新授予)` |

**修正此前表述**：这不是"隐蔽指纹采集器"，而是一个**带降级梯度的定位权限获取流程**（要精确 → 退而求其次近似 → 再不行 NONE），并且会主动弹系统权限框。

### 29.4 关于"是否上传"的边界

**[不可判定]** `b2q` / `a2q` 的引用点仅 5 个文件（`bi`、`b2q`、`a2q`、`ps20`、`riz`、`qs20`），全部在定位功能内部。**静态无法证明该精度档位是否被写进遥测或请求体** —— 若要确认，需要追 `ps20` / `riz` / `qs20` 的调用链到网络层，本报告不据此下结论。

### 29.5 定位的用途边界

dex 字符串明确写出：

```text
"Precise location was not granted: Claude has approximate-only location access
 on this device, Android had no recent approximate position to return, and it
 does not compute a fresh one for approximate-only apps."
```

**[推断]** 定位服务于功能（本地化类工具）。这条文案本身说明：仅近似授权时，若系统没有近期位置就直接返回不了，而不会退化成"用 IP 粗定位"—— 即**定位与地区判定是两条独立链路**。

### 29.6 排除项：SIM / 网络国家码不用于地区判定 [观测]

`getNetworkCountryIso()` / `getSimCountryIso()` 只出现在 WebRTC / 语音编码路径（`defpackage/xp0.java:413`），回退到 `Locale.getDefault().getCountry()`，**不参与地区判定**。

## 30. 时区：走 Datadog RUM，不注入 prompt [观测]

Android 侧没有 `Intl` / `TimeZone.getDefault()` 形式的 prompt 注入，也没有 `<env>Timezone:` 模板。时区与语言、运营商一起出现在 RUM 设备上下文（见 26.4）。

配置默认值 —— `defpackage/cda.java`（注意多项为**关闭**）：

```java
this.C1 = bVar.c("telemetry.metrics.enabled", true, new String[0]);
         bVar.c("telemetry.dependency-collection.enabled", true, new String[0]);
         bVar.c("telemetry.log-collection.enabled", false, new String[0]);
this.R0 = bVar.c("trace.client-ip.enabled", false, new String[0]);
this.S0 = bVar.c("remote_config.enabled", true, new String[0]);
this.T0 = bVar.c("remote_config.integrity_check.enabled", false, new String[0]);
this.U0 = bVar.k("remote_config.url");
this.V0 = bVar.d("remote_config.poll_interval.seconds", 5.0f);
this.W0 = bVar.e("remote_config.max.payload.size", 5120, new String[0]) * 1024;
         bVar.l("rc.targets.key.id",
             "5c4ece41241a1bb513f6e3e5df74ab7d5183dfffbd71bfd43127920d880569fd",
             new String[0]);
         bVar.l("rc.targets.key",
             "e3f1f98c9da02a93bb547f448b472d727e14b22455235796fe4986385...",
             new String[0]);
```

> `remote_config` 具备启用开关、URL、5 秒轮询、5 MiB 载荷上限、带签名 targets ⇒ 地区策略、attestation 策略、完整性检查都能服务端随时改值，无需发版。**因此"默认值"不等于"线上值"。**

## 31. UI / 强制下线证据 [观测]

### 31.1 地区文案 —— `apktool/res/values/strings.xml`

```xml
<string name="error_region_unavailable">Claude isn’t available in your region.
  <a href="https://www.anthropic.com/supported-countries">See supported countries</a></string>

<string name="error_region_missing">There was an error logging in. If you believe
  you received this message in error, please
  <a href="https://support.claude.com/">contact support</a>.</string>
```

两条不同文案 ⇒ 两条不同路径：**地区不支持**（`region_unavailable`）与 **地区判定失败**（`region_missing`）。后者要求联系客服，说明被当作异常而非正常拒绝。

### 31.2 账号受限页 + 申诉入口 —— `defpackage/tb.java`

```java
public final String a() {
    switch (this.a) {
        case 0: return "claudeai.account.restricted.appeal_tapped";
        case 1: return "claudeai.account.restricted.sign_out_tapped";
        case 2: return "claudeai.account.restricted.viewed";
        // ...
    }
}
```

### 31.3 强制下线理由 —— `defpackage/w7l.java` case 9–20

```java
case 9:
    return ln4.m("com.anthropic.claude.analytics.events.LoginEvents.GoogleAccountRequestEnding",
        zcl.values(),
        new String[]{"unspecified", "account_picked", "dismissed", "failed", "withdrawn"}, ...);
case 11:
    return ln4.m("...LoginAttemptMethod", bdl.values(),
        new String[]{"unspecified", "email_code", "email_link", "google",
                     "sso", "apple", "microsoft"}, ...);
case 13:
    return ln4.m("...LoginAttestationExtraRequest", ddl.values(),
        new String[]{"unspecified", "none", "automatic"}, ...);
case 14:
    return ln4.m("...LoginAttestationStep", fdl.values(),
        new String[]{"unspecified", "email_code", "email_link", "google"}, ...);
case 15:
    return ln4.m("...LoginClientErrorKind", gdl.values(),
        new String[]{"unspecified", "network", "credential_no_account",
                     "credential_interrupted", "credential_provider_error",
                     "credential_unknown", "cloudflare_blocked",
                     "client_exception"}, ...);
case 17:
    return ln4.m("...LogoutReason", jdl.values(),
        new String[]{"unspecified", "user_initiated", "server_session_invalid",
                     "missing_organization", "intune_enrollment_invalid",
                     "intune_init_failed", "endpoint_changed",
                     "account_deleted", "trusted_device_relogin",
                     "account_restricted"}, ...);
case 18:
    return ln4.m("...SessionEndClass", kdl.values(),
        new String[]{"unspecified", "routine", "deliberate", "unknown"}, ...);
```

要点：

- `LogoutReason` 含 `account_restricted` ⇒ 服务端可直接踢下线；
- `LoginClientErrorKind` 含 `cloudflare_blocked` ⇒ 登录被 Cloudflare 拦是独立错误类，与地区错误分开记录；
- `LoginAttestationStep` = 登录路径；`LoginAttestationExtraRequest` = 服务端是否额外要证明（`automatic` / `none` / 未要求）。

---

# 第五部分　综合分析

## 32. VPN 为何无效：机制拆解

```text
用户挂 VPN
   ↓
出口 IP 变成目标国机房段          ← 唯一被改变的变量
   ↓
服务端同时持有：
   · 系统时区（Desktop prompt / CLI prompt / Android RUM）
   · 系统语言 locale
   · 持久设备标识（ant-did / machineID / 设备密钥）
   · 硬件画像（cpu_model / os_build / device_class）
   · Play 账户国家（Android，Google 侧）
   · 手机号归属地（Android）
   · SIM 运营商（Android）
   · 设备登记状态与 revoked_at
   ↓
一致性比对失败 → 拒绝
```

**最容易踩的两组组合：**

| 组合 | 信号来源 |
|---|---|
| 美国 IP + `Asia/Shanghai` 时区 | 时区 vs IP |
| 美国 IP + `zh-CN` locale + 中国手机号 | locale / 号码 vs IP |

## 33. 封禁链路（三端汇总）

```text
① 客户端采集（VPN 不改变以上任一）
        ↓
② 服务端评估
   · IP ↔ 时区 / locale 一致性
   · 设备登记状态与吊销
   · 账号状态
   · policy_limits.compliance_taints / RegionSupport
   · 辖区规则（regime）
   · 模型归属
        ↓
③ 拒绝形态（七种，粒度从粗到细）
   · region_unavailable                 → 边缘层（Cloudflare）
   · ip_restricted / ip_not_in_allowed_range → 网络层
   · restricted_regime_endpoint         → 辖区层
   · signups_disabled_in_region / unsupported_phone_number_geo → 地区层
   · account_on_hold / organization_disabled → 账号层
   · account_banned                     → 封号
   · untrusted_device / device_key_missing / missing_client_attestation → 设备层
   · model_access_refused               → 模型层（可静默回退）
   · verification_required              → 转身份 / 年龄验证
        ↓
④ 客户端只做映射与重试
   enrollTrustedDevice()、[regime-refusal] 重发、模型回退、DLP / 安全拦截提示
```

**结论**：真正让人"换了 VPN 还是被封"的，主要不是 IP，而是 **设备密钥 + 设备登记状态 + 时区 / locale 一致性 + 账号状态** 四者的组合。

## 34. 设备级 ban 的可解除性

### 34.1 先分清两个被混称的"设备"概念

| 概念 | 端点 / 载体 | 性质 |
|---|---|---|
| **device registry** | `POST /api/organizations/:orgUUID/cowork/remote_devices` | 服务端登记一行 `{id, public_key, revoked_at}`；公钥须为 P-256 未压缩点，87 字符 base64url |
| **trusted device token** | 登录时本机登记，本地缓存 | 本地 bearer；`clearTrustedDeviceToken` 清的是它，不是服务端行 |

清掉后者只会重新走一次登记流程，前者那一行仍在服务端。

### 34.2 本地密钥层：可重置，且是设计内路径 [观测]

```js
// 按 accountUuid 取密钥；有缓存 rowPk 且非 relearn → 直接复用
let s = await R().loadOrCreate(e, n);
if (s.rowPk && !i) return <cached>;

// relearn 路径：强制重新登记
async function lhs(e, r, n, i){ return await q(e, n, i, 2), wYt(e, r, i, { relearn: true }) }

// 吊销后主动销毁本地密钥，重试并校验确实已删
if (s?.publicKeySpkiB64 !== r) return;
if (i === 0) throw W("it is still stored after being dropped");
// "deviceRegistry: the removed device's key could not be retired"  ← 必须退役
```

其他分支：

```text
[deviceKey] stored device key is unreadable; minting a new one
[deviceKeyStore] file read failed: .corrupt-…        // 损坏隔离后重建
```

> 删掉 `Claude Code-device-keys`（或降级路径 `.device-keys`）后，客户端生成新密钥并登记成**新的一行设备**。这不是破解 —— 换新机器、重装系统、keychain 被清，走的都是同一条 `relearn` 路径。

### 34.3 服务端登记层：客户端改不了 [观测]

```js
var De = "/api/organizations/:orgUUID/cowork/remote_devices";
var Ke = "cowork_remote_device_limit_reached";   // "deviceRegistry: account device limit reached"
var he = "account_session_invalid";
var Se = "cowork_remote_device_registration_revoked";

// 注册返回 201 才算成功；以下情况抛错并带公钥
if (c === Se || (a.status === 409 && c === undefined)) throw new g$e(s.publicKeySpkiB64);
if (a.data?.revoked_at !== null && a.data?.revoked_at !== undefined) throw new g$e(...);
```

- 吊销记录（`revoked_at`）与设备列表是**账号 / 组织侧状态**，本地无写入口；
- `cowork_remote_device_limit_reached` 是硬上限 —— 每次"换新设备"**消耗一个配额**；
- 客户端所有 `clear*` / `forget*` 只清本地 token 与本地密钥。

### 34.4 Android 侧的特殊性：设备 ban 不是一个状态 [观测]

Android 拒绝码里**没有**独立设备封禁状态码。与设备相关的只有三个"证明通不过"类：

```text
missing_client_attestation
device_check_unavailable
trusted_device_attestation_failed
```

不存在 `device_banned` / `device_revoked`。

**[推断] 因此在 Android 上"设备级 ban"不是持久状态，而是"该设备的证明通不过"这个结果：**

1. 账号封禁有状态（`account_banned` / `account_restricted`），换设备无效；
2. 设备侧只有证明校验，本地密钥可重生（`markNeedsReenrollForAttestation`、登出清 `legacyTrustedDeviceKeys` / `legacyTrustedDeviceRow`），技术上可绕 —— 但绕过后面对的仍是**同一账号状态**；
3. 会随设备变化的只有设备登记配额与历史（按 `:orgUUID` 作用域），换设备会产生"同账号短时间重复登记新设备"这一更强信号；
4. `unsupported_phone_number_geo` 与 Play 账户国家**与设备无关**，换设备、换 VPN、换账号都要对齐。

### 34.5 结论

1. **设备行可以换，但换行不等于解封。** 服务端保留 `revoked_at` 与设备上限；换新密钥的成本是一个配额，收益是产生更强的滥用信号。
2. **账号级封禁与设备级无关。** 反过来，设备被吊销时账号可能完好 —— 症状是"能登录，但云端会话 / 远程控制接不上"。
3. **客户端的"恢复"动作全是自动补救，不是解锁开关。** `enrollTrustedDevice()`、`withUntrustedDeviceRecovery()`、`[regime-refusal]` 重发，都是在**合法路径**上把请求重做一遍。
4. **唯一真正能删设备行的路径在服务端**：`/api/organizations/:orgUUID/cowork/remote_devices` 归组织管理员操作。
5. **[推断]** 设备上限是每账号还是每组织、重复登记是否触发额外风控、被吊销设备重新登记是否放行 —— 服务端策略，样本内不可见。
6. **另有独立设备配对错误组**（不属于 device registry）：`duplicate_device_id`、`device_name_in_use`、`device_session_limit`，由同一判定函数（`GGs()`）归类。

## 35. 静态分析边界

以下项**仅靠读代码不可判定**，不做推测：

| 不可判定项 | 原因 |
|---|---|
| `RegionSupport` 服务端依据哪些字段运算 | 判定在服务端，APK 内只有响应结构 |
| `client_attestation` 的服务端验签策略 | 仅有发送侧字段与本地签名调用 |
| 各 flag 线上实际取值 | `remote_config` 默认值 ≠ 生效值 |
| `remote_config.url` 具体地址 | 运行时下发 |
| `unsupported_phone_number_geo` 的国家名单 | 服务端表 |
| reattest 失败后的服务端处置（软 / 硬拒绝） | 客户端只有重试与重登记路径 |
| Play 账户国家与服务端判定的权重关系 | 客户端只上报 |
| 设备上限是每账号还是每组织 | 服务端策略 |
| 封禁的实际触发阈值 | 服务端风控 |

## 36. 三端对照

| 维度 | Desktop | CLI | Android |
|---|---|---|---|
| 时区 | 注入 prompt `<env>Timezone:` + `Intl` | prompt `- Local timezone:` | Datadog RUM `time_zone` |
| 语言 / locale | `getPreferredSystemLanguages()` / `Intl` | 遥测 | RUM `locale` / `locales` |
| 运营商 / SIM | 无 | 无 | RUM `carrier_name` / `cellular` |
| 定位权限档位 | 无（仅 artifact iframe 权限门控） | 无 | `a2q` 三态精度（NONE/APPROXIMATE/PRECISE） |
| Play 账户国家 | 无 | 无 | `BillingConfig.countryCode` |
| 手机号归属地 | 无 | 无 | `unsupported_phone_number_geo` |
| 设备密钥 | `ant-did` + 设备登记 | `Claude Code-device-keys`（P-256） | `session_reattest/device_key` + `reattest_kid` |
| 设备证明 | `bind_attestation_*` | `bind_attestation_*` | `BindDevice.Attestation` + 会话级 reattest |
| Play Integrity | 无 | 无 | 仅支付，fail-open |
| 服务端策略拉取 | `/api/claude_code/policy_limits`（24h 缓存） | 同 | `RegionSupport` + `remote_config` |
| 地区拒绝码 | `ip_restricted` / `ip_not_in_allowed_range` / `restricted_regime_endpoint` | 同 + `lane_unavailable` | `region_missing` / `signups_disabled_in_region` / `region_unavailable`（边缘） |
| 账号封禁码 | `account_banned` / `account_on_hold` | `organization_on_hold` / `org_access_revoked` | `account_banned` / `account_restricted`（LogoutReason） |
| 原生 VPN 探测 | ✅ macOS `utun*` / `scutil --nc list` | ❌ | ❌ |

---

## 37. 目录候选表与数据位置 `[观测]`

`index.chunk-BfOAx4v9.js @862179` 给出了 App 自己认可的**全部候选目录**：

常量分别声明于两处（此处合并展示）：

```js
// @852516 附近
var XBe = "ant-did", ZBe = "-Data";

// @859045 附近
var zl = "-3p", Bl = "Claude", PVe = `${Bl}`,
    FVe = "Claude_pzs8sxrjxfjjc",
    IVe = [ FVe, "AnthropicPBC.Claude_fnn82j28hfe8t" ],
    LVe = `${PVe}${zl}`,                   // "Claude-3p"
    Vl  = `${Bl}${zl}`,                    // "Claude-3p"
    RVe = "Claude-NativeHost";

var aHe = {
  appData:     { at: () => a.app.getPath("appData"), msix: "Roaming" },
  logsParent:  { at: () => n.dirname(a.app.getPath("logs")) },
  localAppData:{ at: () => process.env.LOCALAPPDATA, msix: "Local" }
};

var oHe = {
  darwin: [ ["appData", Bl], ["appData", Vl],       // Claude / Claude-3p
            ["logsParent", Bl], ["logsParent", Vl] ],
  linux:  [ ["appData", Bl], ["appData", Vl] ],
  win32:  [ ["appData", Bl],
            ["localAppData", Bl],
            ["localAppData", `${Bl}${ZBe}`],        // Claude-Data
            ["localAppData", Vl],                   // Claude-3p
            ["appData", Vl],
            ["appData", RVe] ]                      // Claude-NativeHost
};

function sHe(){
  return (oHe[process.platform] ?? []).flatMap(([e, t]) => {
    let { at: r, msix: i } = aHe[e], a = r();
    return a ? [ n.join(a, t), ...i ? BVe(i, t) : [] ] : [];
  });
}

function cHe(){
  return process.env.CLAUDE_USER_DATA_DIR ? []
    : [...new Set([ ...sHe(), ...KVe(), ...XVe(),
        ...process.platform === "darwin" ? [nHe()] : [] ])];
}
```

其中 `Bl = "Claude"`、`Vl = "Claude-3p"`。

### 展开后的实际路径

| 平台 | 路径 |
|---|---|
| macOS | `~/Library/Application Support/Claude` |
| macOS | `~/Library/Application Support/Claude-3p` |
| macOS | `~/Library/Logs/Claude` |
| macOS | `~/Library/Logs/Claude-3p` |
| Windows | `%APPDATA%\Claude` |
| Windows | `%LOCALAPPDATA%\Claude` |
| Windows | `%LOCALAPPDATA%\Claude-Data` |
| Windows | `%LOCALAPPDATA%\Claude-3p` |
| Windows | `%APPDATA%\Claude-3p` |
| Windows | `%APPDATA%\Claude-NativeHost` |
| Windows | `%LOCALAPPDATA%\Packages\<PFN>\LocalCache\…`（MSIX 虚拟化） |

MSIX 包族名 `[观测]`：`Claude_pzs8sxrjxfjjc`、`AnthropicPBC.Claude_fnn82j28hfe8t`。

### 日志目录的 `-3p` 处理

```js
function nHe(){
  let e = a.app.getPath("logs"),
      t = e.endsWith("-dev") ? "-dev" : "",
      n = t ? e.slice(0, -t.length) : e;
  return `${n.endsWith(zl) ? n.slice(0, -3) : `${n}${zl}`}${t}`;   // zl = "-3p"
}
```

`nHe()` **强制**加 `-3p` 后缀（已有则去掉再加，保持单一后缀），并保留 `-dev`。

### 配置库目录

```js
function $Ve(){ return n.join(Hl(), "configLibrary") }
function Wl(e){ return n.join($Ve(), `${e}.json`) }
function eHe(){ return n.join($Ve(), "_meta.json") }
```

即 `<userData>/configLibrary/<name>.json` 与 `_meta.json`。

### 目录名参与遥测

`NK()` 暴露的字段已含 `deploymentMode`；目录名后缀 `-3p` 与之对应。同时 `Mfe()` 把安装渠道折成两值：

```js
function Mfe(){ return $r() ? "msix" : "squirrel" }
```

---

## 38. 同级目录扫描 `[观测]`

`index.chunk-CxzPVbs5.js @5449`

```js
async function re(){
  await n.S();
  let e = c.app.getPath("userData"), r = t.S5();
  let i = new Set([ c.app.getPath("appData") ]);
  let a = t.het("CLAUDE_E2E_IMPORT_SIBLING_PARENT");
  a && (i.clear(), i.add(a));
  let o = new Set, l = [];
  let u = (e) => { o.has(e.rootPath) || l.length >= p || (o.add(e.rootPath), l.push(I(e))) };

  r !== e && await N(r) === "userData" && u({ label: P(basename(r)), rootPath: r, origin: "sibling-1p" });
  await q() > 0 && u({ label: F(x()), rootPath: x(), origin: "terminal" });
  await He(await n.h()) > 0 && u(L(e));

  for (let t of i){
    let n = await readdir(t).catch(() => []);
    for (let i of n){
      if (!i.startsWith("Claude")) continue;              // ← 扫所有 Claude* 目录
      let n = join(t, i);
      n !== e && n !== r && await N(n) === "userData"
        && u({ label: P(i), rootPath: n, origin: "sibling-3p" });
    }
  }
  return l;
}
```

**判定条件只是 `startsWith("Claude")`**，因此 `Claude-3p`、`Claude-Data`、`Claude-NativeHost`、乃至任何以 `Claude` 开头的同级目录都会被列为“可导入的其他账号”。

对应的持久化标记：`sibling-import.json`、`sibling-import-declined.json`，以及环境变量 `CLAUDE_DESKTOP_SIBLING_IMPORT_ORG`。

---

# 附录

## A. 证据索引

### 桌面端（`extract/mac/asar/.vite/build/`）

| 文件 | 承载的发现 | 报告节 |
|---|---|---|
| `index.chunk-BfOAx4v9.js` | `<env>` 模板、`jAn()` 遥测 envelope、`Kv()` 指纹头、`I2r/L2r/R2r/z2r` VPN 探测、`Xgt()` locale、endpoint 策略表、错误码枚举 | 5, 7, 8, 9, 10, 11, 12 |
| `index.chunk-DuQJhuk4.js` | `{{currentTimezone}}` 填充实现 | 5 |
| `index.chunk-DWOgY7DF.js` | 错误码 → UI 状态映射 | 11 |
| `index.chunk-DIjipm-e.js` | `policy_limits` 完整模块 | 16 |
| `index.chunk-oZ3hATSw.js` | 设备证明失败集合 | 14 |
| `index.chunk-OpG9r3HN.js` | `untrusted_device` → `enrollTrustedDevice()` | 14 |
| `index.chunk-Ghv0q1hg.js` | managed-settings 网关 IP 说明文案 | 21 |

### CLI（`/tmp/claude_strings.txt`，源 `claude_副本`）

| 符号 / 字符串 | 承载的发现 | 报告节 |
|---|---|---|
| `Claude Code-device-keys`、`.device-keys`、`prime256v1`、`ieee-p1363` | 设备密钥 | 14 |
| `cowork/remote_devices`、`cowork_remote_device_limit_reached` | 设备注册与上限 | 15, 34.3 |
| `xK` / `EA` / `OK` / `MK` / `ce` 集合 | 拒绝码分类 | 17 |
| `[regime-refusal]`、`api_regime_refusal_recovery` | 辖区限制 | 18 |
| `model_access_refused`、`[model-access] now using` | 模型门控 | 19 |
| `api_request_dlp_denied` 等 | 内容合规遥测 | 20 |
| `Vt("access.denied", {...})` | 组织网关 IP 策略 | 21 |
| `https://anthropic.com/supported-countries` | 预检提示 | 22 |

### Android（`extract/apk2/jadx/sources/defpackage/`）

| 文件 | 承载的发现 | 报告节 |
|---|---|---|
| `y9t.java` | `RegionSupport` 序列化器 | 24 |
| `j5w.java` | `SendPhoneVerificationCodeRequest` | 24 |
| `j08.java` | 注册 / 登录 / 账号拒绝码枚举 | 25.1 |
| `m08.java` | 手机号 / 验证拒绝码枚举 | 25.2 |
| `l4j.java` | Play 商店国家查询（case 18） | 26.1 |
| `py20.java` | `VerifyGoogleRequest`（5 字段） | 27 |
| `h3w.java` | 邮箱登录 attestation | 27 |
| `hu30.java` | attestation 状态机 `pending` / `not_asked` | 27 |
| `x7h.java` | 订阅购买 Play Integrity | 28.1 |
| `wkq.java` | 额度购买 Play Integrity | 28.2 |
| `o7j.java` | Integrity token 铸造 | 28.3 |
| `vds.java` | `PurchaseAttestation` 载荷 | 28.3 |
| `bi.java` / `a2q.java` / `b2q.java` | 定位权限三态精度 + 获取流程 | 29 |
| `cda.java` | Datadog / remote_config 默认值 | 30 |
| `r8.java` | `AccountLogoutCleaner` | 26.3 |
| `tb.java` | 账号受限 / 申诉遥测 | 31.2 |
| `w7l.java` | `LogoutReason` / `LoginClientErrorKind` 等枚举表 | 31.3 |
| `xp0.java:413` | `getNetworkCountryIso` 非地区判定（排除项） | 29 |

## B. 复现命令

```bash
# ── 桌面端 ──────────────────────────────────────
# 1) 解包 Electron ASAR
python3 tools/asar_extract.py <app.asar> <out>

# 2) 时区注入点
grep -n 'currentTimezone' out/.vite/build/*.js

# 3) 遥测 envelope
python3 -c "d=open('out/.vite/build/index.chunk-BfOAx4v9.js').read(); \
  i=d.find('async function jAn('); print(d[i:i+3200])"

# 4) VPN 探测
grep -n 'utun\\d+|ppp' out/.vite/build/*.js

# 5) locale 采集
grep -n 'getPreferredSystemLanguages' out/.vite/build/*.js

# 6) 遥测出口白名单
grep -n 'datadog-rum\|anthropic-telemetry' out/.vite/build/*.js

# 7) policy limits 模块
head -c 3200 out/.vite/build/index.chunk-DIjipm-e.js

# ── CLI ─────────────────────────────────────────
# 8) 提取明文 JS（Bun 单文件）
strings -a claude > /tmp/cc.txt

# 9) 设备密钥 / 设备注册
grep -F 'Claude Code-device-keys' /tmp/cc.txt
grep -F 'cowork/remote_devices'   /tmp/cc.txt
grep -F 'bind_attestation'        /tmp/cc.txt

# 10) 拒绝码全集
python3 - <<'PY'
import re
d = open('/tmp/cc.txt', encoding='utf-8', errors='replace').read()
print(sorted(set(re.findall(r'regime_[a-z_]+|"ip_[a-z_]+"|refused_[a-z_]+', d))))
PY

# 11) 组织网关 IP 策略
grep -o 'access.denied.\{0,120\}' /tmp/cc.txt | head

# ── Android ────────────────────────────────────
# 12) 反编译（沙箱内必须重定向 Java home）
export _JAVA_OPTIONS="-Duser.home=$PWD/.cache/home"
jadx -d extract/apk2/jadx extract/apk2/base.apk

# 13) 资源解码
apktool d -f --no-src -o extract/apk2/apktool extract/apk2/base.apk

# 14) 地区判定入口
grep -rn 'RegionSupport' extract/apk2/jadx/sources/defpackage/ | head

# 15) 拒绝码枚举
sed -n '1,80p' extract/apk2/jadx/sources/defpackage/j08.java
sed -n '1,80p' extract/apk2/jadx/sources/defpackage/m08.java

# 16) Play 账户国家
grep -n 'Play Store country lookup failed' \
  extract/apk2/jadx/sources/defpackage/l4j.java

# 17) 登录 attestation 字段表
grep -n 'l("' extract/apk2/jadx/sources/defpackage/py20.java

# 18) Play Integrity 三处调用点
grep -rn 'play_integrity_purchase_attestation\|credit_purchase_attestation' \
  extract/apk2/jadx/sources/defpackage/

# 19) 由 dex 复核字符串（不依赖反编译质量）
strings -a extract/apk2/raw/classes*.dex > /tmp/news.dex.txt
grep -o 'signups_disabled[a-z_]*\|region_[a-z_]*\|unsupported_phone_number_geo' \
  /tmp/news.dex.txt | sort -u
```

**工具链**：`7z`（DMG/HFS 直读，无需挂载）、`unzip`（MSIX）、`jadx`、`apktool`、`otool`、`codesign`、`strings`。

**jadx 踩坑**：沙箱禁写 `~/Library/Caches/io.github.skylot.jadx`，需 `export _JAVA_OPTIONS="-Duser.home=..."`；设 `HOME` / `XDG_CACHE_HOME` 无效。

## C. 已确认不存在的机制 [观测]

| 能力 | 结论 | 证据 |
|---|---|---|
| GPS / 精确定位采集（桌面） | 无 | `claude-native-binding.node` / `computer_use.node` 的 `otool -L` 不含 `CoreLocation.framework`；只有 Security / CoreFoundation / CoreGraphics / AppKit |
| `NSLocationUsageDescription` | 存在但非定位用 | 用于 artifact iframe 的 `geolocation` / `geolocation-approximate` 权限门控（`iIn()`），文案「for content that you allow to use it」 |
| 内置国家名单 / OFAC / 制裁表（桌面 + CLI） | 无 | `supportedCountries` / `SUPPORTED_COUNTRIES` / `countryCode` / `cf-ipcountry` 在 desktop bundle 与 CLI 中均 0 命中 |
| `getNetworkCountryIso` 用于地区判定（Android） | 否 | 仅出现在 WebRTC / 语音编码路径（`xp0.java:413`），回退 `Locale.getDefault().getCountry()` |
| 原生 VPN 探测（Windows / CLI） | 无 | MSIX 同名函数在 `process.platform!=="darwin"` 时早退；CLI 中 `vpnActive` / `vpn_interfaces` 命中 0 |
| 专门的风控 / 反欺诈 SDK（Android） | 无 | Incognia / Forter / iovation / ThreatMetrix / AppsFlyer 均未出现；遥测栈为 Sentry + Segment + Datadog RUM + GrowthBook |
