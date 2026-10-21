# Claude 身份验证（KYC）机制逆向分析

**样本**：`com.anthropic.claude` 1.261019.20（Play Store 分包 APK）
**分析方法**：纯静态 —— `classes*.dex` 字符串枚举 + jadx 反编译源码。不做运行、不触发验证流程。
**证据分级**：`[观测]` 直接读到的代码/字符串 · `[推断]` 合理外推 · `[不可判定]` 静态无法确定

---

## 1. 一句话结论

**客户端里没有任何身份验证的采集或判定实现。** 它只做三件事：查状态、打开一个服务端下发的托管页 URL、轮询结果。

护照图像与证件号**不经过 Anthropic 客户端**。客户端最终拿到的只是一个 verdict（判定结果），因此判定逻辑、证件留存、跨账号关联全部在服务端与托管厂商侧。

---

## 2. KYC 状态机 `[观测]`

`extract/apk2/jadx/sources/defpackage/asj.java`

```java
/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
public final class asj {
    public static final r2k u;
    public static final asj v;
    public static final /* synthetic */ asj[] w;

    static {
        asj asjVar  = new asj("NOT_REQUIRED",  0);
        asj asjVar2 = new asj("VERIFIED",      1);
        asj asjVar3 = new asj("CREATED",       2);
        asj asjVar4 = new asj("IN_PROGRESS",   3);
        asj asjVar5 = new asj("MANUAL_REVIEW", 4);
        asj asjVar6 = new asj("FAILED",        5);
        asj asjVar7 = new asj("EXPIRED",       6);
        asj asjVar8 = new asj("DENIED",        7);
        asj asjVar9 = new asj("UNKNOWN",       8);
        v = asjVar9;
        w = new asj[]{ asjVar, asjVar2, asjVar3, asjVar4, asjVar5,
                       asjVar6, asjVar7, asjVar8, asjVar9 };
        u = yga.A(2, new ndj((byte) 6));     // ← 序列化 selector
    }

    public final boolean a() {               // ← 是否「需要拦截」
        switch (ordinal()) {
            case 0:   // NOT_REQUIRED
            case 1:   // VERIFIED
            case 6:   // EXPIRED        ← 不拦截
            case 8:   // UNKNOWN
                return false;
            case 2:   // CREATED
            case 3:   // IN_PROGRESS
            case 4:   // MANUAL_REVIEW
            case 5:   // FAILED
            case 7:   // DENIED         ← 拦截
                return true;
            default:
                gp.p();
                return false;
        }
    }
}
```

### 状态与阻塞语义对照

| 序号 | 状态 | `a()` 返回值 | 语义 |
|---|---|---|---|
| 0 | `NOT_REQUIRED` | `false` | 无需验证 |
| 1 | `VERIFIED` | `false` | 已通过 |
| 2 | `CREATED` | `true` | 已创建，未开始 |
| 3 | `IN_PROGRESS` | `true` | 进行中 |
| 4 | `MANUAL_REVIEW` | `true` | 人工审核 |
| 5 | `FAILED` | `true` | 流程失败 |
| 6 | `EXPIRED` | **`false`** | **已过期，但不拦截** |
| 7 | `DENIED` | `true` | 被拒 |
| 8 | `UNKNOWN` | `false` | 未知 |

### 关键观察：`EXPIRED` 不拦截

这是状态机里最有信息量的一处不对称。

```java
case 6:  // EXPIRED
    return false;        // 不拦截
case 5:  // FAILED
case 7:  // DENIED
    return true;         // 拦截
```

**设计者预期「过期可以重来」，而「被拒」与「失败」需要拦截。** 这直接说明：同一个证件在 `EXPIRED` 或技术性 `FAILED` 之后重做，是设计内允许的路径。

### 序列化取值表 `[观测]`

`extract/apk2/jadx/sources/defpackage/ndj.java:41`

```java
case 6:
    return ln4.m(
        "com.anthropic.claude.api.kyc.KycStatus",
        asj.values(),
        new String[]{ "not_required", "verified", "created", "in_progress",
                      "manual_review", "failed", "expired", "denied", null },
        new Annotation[][]{ null, null, null, null, null, null, null, null, null });
```

即网络传输使用 `snake_case`，第 9 个位置为 `null`（对应 `UNKNOWN`，无线上取值）。

---

## 3. 响应体结构 `[观测]`

`extract/apk2/jadx/sources/defpackage/bsj.java`

```java
static {
    bsj bsjVar = new bsj();
    a = bsjVar;
    PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor =
        new PluginGeneratedSerialDescriptor(
            "com.anthropic.claude.api.kyc.KycStatusResponse", bsjVar, 6);
    pluginGeneratedSerialDescriptor.l("status", false);            // 唯一必填
    pluginGeneratedSerialDescriptor.l("vendor", true);
    pluginGeneratedSerialDescriptor.l("vendor_inquiry_id", true);
    pluginGeneratedSerialDescriptor.l("vendor_inquiry_url", true);
    pluginGeneratedSerialDescriptor.l("should_poll", true);
    pluginGeneratedSerialDescriptor.l("created_at", true);
    descriptor = pluginGeneratedSerialDescriptor;
}

@Override
public final KSerializer[] childSerializers() {
    bdz bdzVar = bdz.a;
    return new KSerializer[]{
        dsj.e,                    // status
        fm40.H(bdzVar),           // vendor
        fm40.H(bdzVar),           // vendor_inquiry_id
        fm40.H(bdzVar),           // vendor_inquiry_url
        wl4.a,                    // should_poll
        fm40.H(vdj.a)             // created_at
    };
}
```

### 字段表

| 字段 | 类型 | 必填 | 作用 |
|---|---|---|---|
| `status` | `KycStatus` | ✅ | 唯一服务端判定结果 |
| `vendor` | `String?` | — | **厂商名，普通字符串** |
| `vendor_inquiry_id` | `String?` | — | 厂商侧 inquiry ID |
| `vendor_inquiry_url` | `String?` | — | **托管页 URL** |
| `should_poll` | `Bool?` | — | 是否轮询 |
| `created_at` | `Timestamp?` | — | 创建时间 |

**`vendor` 不是枚举，是 `String`。** 说明 Anthropic 更换验证供应商不需要发版，客户端完全按字符串透传。

---

## 4. 关键否定证据：客户端没有集成验证厂商 SDK `[观测]`

| 搜索项 | 命中数 | 结论 |
|---|---|---|
| `withpersona.com` | **0** | 无硬编码托管域名 |
| `persona.com` | **0** | 同上 |
| `com.persona`（包名） | **0** | 无 SDK 包 |
| `persona_`（字段前缀） | **0** | 无 SDK 字段 |
| `Persona`（字符串） | 3 | **全是误命中**：`isOfferPersonalizedByDeveloper`、`XA Personal Finance usage event was dropped`、`Personal` |
| 源码目录 `*persona*` | **0** | 无 SDK 目录 |
| `inquiry` | 1 | 仅 `vendor_inquiry_id` / `vendor_inquiry_url` |

### 顺带排除的其他「疑似采集」痕迹

| 字符串 | 实际来源 | 判定 |
|---|---|---|
| `AGGREGATED_ON_DEVICE_SELFIE_FACE_DETECTION` | **Firebase ML Kit 的枚举常量**（同组还有 `BARCODE_DETECTION`、`POSE_DETECTION`、`SEGMENTATION` 等） | ❌ 非 KYC |
| `guard_liveness_uuid=` | 上报字段名（键），无采集代码 | ❌ 非采集实现 |
| `guard_verdict=` | 同上，verdict 由服务端回填 | ❌ 非采集实现 |
| `guard_verdict_observed_at_ms=` | 同上 | ❌ 非采集实现 |
| `TrueDepth` | **0** | 无 iOS 深度相机调用 |
| `face_verif` | **0** | 无人脸比对实现 |

**`guard_*` 是三个上报字段名**（注意结尾的 `=`），说明 liveness 也是在托管页完成，客户端只把结果的 key 带出来，而不是自己采集。

### 相关但不同的类

```
com.anthropic.claude.app.verification.VerificationScreens
com.anthropic.claude.app.verification.VerificationScreens$VerifyPhoneCodeStep
com.anthropic.claude.app.verification.a
com.anthropic.claude.app.verification.b
```

`VerificationScreens` 是**手机验证码**页面，与 KYC 是两条独立链路（前者对应 `SendPhoneVerificationCodeRequest{ phone_number, client_attestation }`）。

### 字符串存在但无代码路径

```
kyc_required          ← 引导语
KYC_REQUIRED          ← 大写变体（同一组内出现）
```

存在字符串但没有本地判定逻辑，与 `error_region_unavailable` 属于同一类：**文案在客户端，判定在服务端**。

### 端点路径

`[观测]` dex 中**找不到任何 KYC 接口路径**（如 `/api/kyc/...`）—— 只有类名。这与客户端只做「查询 + 打开 URL」的设计一致：端点由服务端在会话语境中提供。

---

## 5. 真实流程 `[推断]`

```
① 客户端 ──► 服务端：本账号 KYC 状态？
          ◄── KycStatusResponse{ status, vendor, vendor_inquiry_id,
                                 vendor_inquiry_url, should_poll, created_at }

② 若 status ∈ {CREATED, IN_PROGRESS, MANUAL_REVIEW, FAILED, DENIED}
   → 打开 vendor_inquiry_url（托管页，App 外 / WebView）

③ 证件采集、活体检测 = 在托管页内完成，数据直达厂商
   Anthropic 客户端不接触证件图像

④ should_poll = true → 轮询 status 直至终态

⑤ 终态：
   VERIFIED      → 放行
   DENIED        → 拦截
   EXPIRED       → 不拦截（可重做）
```

### 为什么这个设计可被推断出来

三点互相印证：

1. **`vendor_inquiry_url` 是完整 URL**，不是厂商特定的 SDK 调用参数
2. **`should_poll` 是布尔**，说明客户端不参与验证过程，只等结果
3. **零 SDK、零域名、零采集代码** —— 如果客户端做采集，这三项必然有

---

## 6. 护照复用分析

### 6.1 三层结构

| 层 | 归属 | 新账号是否重置 | 依据 |
|---|---|---|---|
| **① 账号 KYC 状态** | Anthropic 账号记录 | ✅ **重置** | `KycStatusResponse` 按账号查询，新账号从 `NOT_REQUIRED` 开始 |
| **② 厂商 inquiry 记录** | 验证厂商 | ❓ **取决于配置** | `vendor_inquiry_id` 由服务端下发，客户端不可见厂商库 |
| **③ 证件与生物特征** | 法律/生物身份 | ❌ **无法重置** | 不属于技术标识，无客户端机制可改 |

第 ① 层不构成障碍。**风险集中在 ② 与 ③。**

### 6.2 证件去重能力存在，但是否启用不可见

验证厂商（行业通用能力）通常提供：

```
文档号去重（document number dedup）
人脸重复比对（face duplicate detection）
跨 inquiry watchlist
```

`[不可判定]` —— 客户端拿不到 Anthropic 的具体配置。

但从三处设计可以推断**能力是存在的**：

| 观察 | 推断 |
|---|---|
| `vendor` 是字符串而非枚举 | Anthropic 把厂商抽象掉了，说明验证是**基础设施**，会有统一策略 |
| 存在 `MANUAL_REVIEW` | 有人工介入通道，人工可查历史 |
| `vendor_inquiry_id` 被回传并持久化 | 服务端保留了指向厂商记录的指针 |

`[推断]` 是否有自动去重开关，无法从样本判定。

### 6.3 你上次的状态决定风险 —— 这是最有用的部分

| 上次状态 | 含义 | 复用风险 | 理由 |
|---|---|---|---|
| `VERIFIED` | 已验证通过，后因策略被封 | ⚠️ **最高** | 证件已确认为真实并与你绑定，重新验证会被直接匹配 |
| `DENIED` | 验证被拒 | ⚠️ **高** | 证件已被标记；且 `a()` 返回 `true`，行为上拦截 |
| `MANUAL_REVIEW` | 人工审核 | 🟡 中高 | 人工已接触过材料，取决于最终结论 |
| `FAILED` | 流程失败 | 🟡 中 | **需区分技术性失败**（照片模糊/光线）与判定性失败 |
| `EXPIRED` | 已过期 | 🟢 **低** | **`a()` 返回 `false`，设计上允许重做** |

**`EXPIRED` 与 `FAILED` 的区别最值得利用**：前者明确不拦截，后者的技术性子类（材料不清晰导致的失败）也在设计上可重试。

### 6.4 决定性矛盾：KYC 解决「你是谁」，不解决「你在哪」

这是本分析里最重要的一点。

```
你的封禁理由：region policy（地区不支持）
你要过 KYC：  提交护照（含国籍）+ 人脸
```

**护照国籍是地区判定里最硬的信号之一，比 IP 硬得多。** IP 可以换，护照国籍不能。

所以：

| 情形 | 结果 |
|---|---|
| Anthropic 启用了证件去重 | 新账号一验证即被连回旧账号 |
| 未启用去重 | 这一轮能过，但等于**用真实法律身份注册了一个规避地区政策的账号** |
| 无论哪种 | 你主动提交了证明「你在不支持地区」的最强证据 |

而且结构性问题是：**你的目标（绕过地区限制）和手段（提交真实国籍证件）方向相反。**

### 6.5 与设备指纹的关键区别

| 类型 | 可否重置 | 手段 |
|---|---|---|
| `ant-did` / `machineID` | ✅ 可 | 删文件，下次自动生成 |
| 设备密钥（P-256） | ✅ 可 | `relearn` 路径重新登记 |
| 浏览器指纹 | ⚠️ 需重建环境 | 换真实自洽环境 |
| **护照号** | ❌ **不可** | 无任何技术手段 |
| **人脸** | ❌ **不可** | 无任何技术手段 |

设备层可以清到「看起来是新机器」，但 KYC 层是**法律身份**，没有对应的「重置」概念。只要走 KYC，新账号与旧账号就在身份层面连通了。

---

## 7. 决策参考

| 你的上次状态 | 建议 |
|---|---|
| `VERIFIED` 后因地区被封 | 复用护照会把新账号直接锚定到已封主体。**方向上是反的** |
| `EXPIRED` | 🟢 唯一相对安全的情形，设计上允许重做 |
| 技术性 `FAILED` | 🟢 可重试（材料问题非证件问题） |
| `DENIED` | 不要复用。证件已标记，`a()=true` 拦截 |
| 不确定 | 登录旧账号看验证页文案；或查留存邮件 |

**优先级判断**：KYC 是否会被触发本身由服务端决定（`kyc_required` 是文案，判定不可见）。如果新账号根本不触发 KYC，这个问题就不存在。

---

## 8. 静态边界

| 项 | 状态 | 原因 |
|---|---|---|
| 验证厂商是否为 Persona | **不可判定** | 客户端零 SDK、零域名；`vendor` 只是透传字符串 |
| 是否启用证件号去重 | **不可判定** | 服务端/厂商配置 |
| 是否启用跨账号人脸比对 | **不可判定** | 同上 |
| KYC 触发条件 | **不可判定** | 服务端；`kyc_required` 仅为文案 |
| 证件图像是否留存 | **不可判定** | 客户端不接触，厂商侧策略 |
| 地区判定是否使用护照国籍 | `[推断]` 极可能 | 无直接代码证据 |
| KYC 端点路径 | **不可判定** | dex 中无路径字符串 |
| `guard_verdict` 的判定阈值 | **不可判定** | 仅上报字段名，判定在服务端/厂商 |

---

## 9. 复核命令

```bash
export _JAVA_OPTIONS="-Duser.home=$PWD/.cache/home"

# ── 状态机与阻塞语义
sed -n '/public final boolean a/,/^}/p' \
  extract/apk2/jadx/sources/defpackage/asj.java

# ── 状态枚举定义
sed -n '1,40p' extract/apk2/jadx/sources/defpackage/asj.java

# ── 响应体字段表
grep -n 'l("' extract/apk2/jadx/sources/defpackage/bsj.java

# ── 序列化取值（snake_case）
grep -n 'api.kyc.KycStatus"' extract/apk2/jadx/sources/defpackage/ndj.java

# ── 否定证据：无 SDK
find extract/apk2/jadx/sources -type d -iname "*persona*"        # 期望空
find extract/apk2/jadx/sources -type d -iname "*kyc*"            # 期望空

# ── dex 层字符串复核（不依赖反编译质量）
strings -a extract/apk2/raw/classes*.dex > /tmp/news.dex.txt
for k in withpersona.com persona.com com.persona persona_ Persona \
         guard_liveness guard_verdict kyc_required TrueDepth face_verif; do
  printf "%-22s %s\n" "$k" "$(grep -c -i -F "$k" /tmp/news.dex.txt)"
done
```

**期望结果**

```
withpersona.com       0
persona.com           0
com.persona           0
persona_              0
Persona               3      ← 全为 Personalized / Personal 类误命中
guard_liveness        1      ← 仅字段名
guard_verdict         1      ← 仅字段名
kyc_required          1
TrueDepth             0
face_verif            0
```

---

## 10. 与现有报告的关系

本文档是补充章节，独立于主报告：

| 文档 | 内容 |
|---|---|
| `claude-region-detection-report.md` | 地区检测 / 封禁链路 / 设备指纹（36 节） |
| `claude-reinstall-checklist.md` | 新环境终检清单（8 个 Gate） |
| **`claude-kyc-analysis.md`**（本文） | 身份验证机制与护照复用分析 |

**共通结论**：三份文档指向同一架构特征 —— 决策在服务端，客户端只负责采集信号、透传 verdict、展示文案。KYC 是这一模式最纯粹的体现：客户端连证件都看不到。
