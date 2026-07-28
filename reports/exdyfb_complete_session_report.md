# exdyfb (dh151) 完整分析报告 — 从协议逆向到节点获取全流程

**样本代号**：exdyfb
**文件位置**：`/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/exdyfb_original.apk`（约 69MB）
**包名**：`bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns`
**内部代号**：`dh151`
**来源**：福建管局下发，2026-07-16 首次发现
**应用伪装**：仿 Telegram 的即时通讯客户端（"Teamgram" 系）
**报告日期**：2026-07-28（本次会话）

---

## 一、样本基本信息

| 属性 | 值 |
|---|---|
| 包名 | bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns |
| app_name（内部） | dh151 |
| 通信端口 | 30151 |
| AES-key | qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb |
| 伪装 SNI | www.bootcdn.cn |
| app_domain（.dat配置域） | *.qianchixt.com |
| 加固壳 | 有，自定义 XXTEA+AES-256-CBC + InMemoryDexClassLoader，classes.dex 是伪装成目录的垃圾文件集合 |
| 关键 native 库 | `libgojni.so`（Go 编写的 forwarder-control SDK）、`libSgzqvwvAiApn.so`（C++ 编写的 tgnet/MTProto 层，23.8MB） |
| 目标端 IP 池 | app_line_ips，服务端通过 MTProto 会话动态推送，非静态配置 |

---

## 二、静态基础链路（离线可完成）

以下环节全部可以**不运行 APP、纯静态**完成，且已实测验证：

1. **RSA 私钥提取**：从 APK 内搜索双层 base64 隐藏的 PEM 私钥，解密 bootstrap 种子
2. **bootstrap 解密**（RSA-2048 PKCS#1 v1.5）：得到 `SecretPayload{ AppDomain, AppDomainPort, AppName, SDKVersion, AESKey }`（**注意此结构体只有 5 个字段，不含 app_line_ips**，与早期文档的猜测不同，已用 Ghidra 结构体 dump 确认）
3. **桶名/文件名预测算法**：`md5(YYYYMMDD + app_name + cloud_tag + sdk_version)`，桶名=前16位，文件名=后16位，三云（阿里云 OSS / 百度云 BOS / 天翼云 ZOS）并行尝试
4. **.dat 文件解密**（AES-256-CBC，IV=key[:16]，PKCS7 padding）：得到 `{"nodesA":[...]}` 格式的 **控制面节点**（3个），与最终的 app_line_ips（代理节点池）**完全不重叠**，是两套不同的 IP 集合
5. **DNS TXT 通道**：查 `_dns.{app_domain}` 等子域的 TXT 记录，AES 解密得到控制面 IP（旁路验证手段）

**实测验证**（本次会话，2026-07-26/27）：用上述算法对当天日期实际下载解密，控制面节点结果与历史记录完全吻合，证明算法本身长期稳定有效，可对同家族其余样本直接复用。

---

## 三、Forwarder Control 协议逆向 — 一条已证实的"死胡同"

早期怀疑 app_line_ips（15~24个真正的代理转发节点）是通过 `libgojni.so` 里一套 HMAC 认证的私有协议（"forwarder control"）向控制面节点请求得到的。本次会话对这条协议做了**完整的静态逆向 + 实机验证**，结论是：**协议本身逆向完全正确，但它在实际运行中从未被调用**，不是获取节点的真实路径。记录如下，供后续排除干扰：

### 3.1 协议细节（已用 Ghidra 反编译 + capstone 校验）

- 传输层：TLS 1.3，**必须用 Go 的 TLS 指纹**（`utls` 库的 `HelloGolang`，不是 Chrome 指纹）+ ALPN `cursor-control-v1`
- 服务端按 TLS 指纹分流：Chrome 指纹 → 协商到 `h2`（走的是普通代理转发通道）；Go 指纹 → 协商到 `cursor-control-v1`（forwarder control 通道）。这解释了早期所有"直连被 302 重定向"的失败案例。
- 请求体：明文 JSON `fwdHelloRequest{version, type, app_name, sdk_version, device_id, timestamp_unix, nonce, mac}` + `\n`，4字节大端长度前缀
- MAC 算法（从 ARM64 汇编逐指令确认）：`hex(HMAC-SHA256(KEY, "v1|hello|"+app_name+"|"+sdk_version+"|"+device_id+"|"+versionStr+"|"+tsStr+"|"+nonce))`
- 关键函数地址（Ghidra 地址，`libgojni.so`，image base=0x100000）：
  - `hmacSHA256Hex` @ 0x53f610（实际文件偏移 0x43f610）
  - `signForwarderHelloMAC` @ 0x53f2a0
  - `tryForwarderControlEndpoints` @ 0x541390
  - `FetchForwarderFixedTuple` @ 0x53f900
  - `doForwarderControlFetch` @ 0x540980

### 3.2 为什么最终判定"未被使用"

在真机上对 `hmacSHA256Hex` 和 `tryForwarderControlEndpoints` 两个函数入口分别打入 ARM64 汇编探针（详见第五节的插桩技术），用环形缓冲区记录调用次数，跑了 5 分钟以上、多种触发条件（清缓存冷启动、iptables 封锁全部已知节点强制走 failover），**两个探针的调用计数始终为 0**——证明这条 HMAC 协议链路，在这个具体版本的样本里，压根没有被执行过。

**关键教训**：反编译代码里存在的协议不等于运行时真正在用的协议。加固/混淆样本里常见"看起来完整、实际是废弃或备用"的代码路径，必须用运行时插桩验证，不能只靠静态反编译下结论。

详见 `reports/forwarder_control_protocol_FINAL.md`（含完整协议规范和当时的离线客户端代码）。

---

## 四、真正的机制：MTProto 层的 onIpListReceived 回调

### 4.1 发现过程

在两个 HMAC 相关探针始终为 0 的同时，观察到 app 依然能正常拉到新的 `app_line_ips`（`sdk_forwarder_fixed.json` 内容会更新）。反查脱壳后的 Java 源码，在 `org.telegram.tgnet.ConnectionsManager.java` 里找到：

```java
public static void onIpListReceived(int i, String[] strArr) {
    JSONArray jSONArray = new JSONArray();
    for (String str : strArr) jSONArray.put(str);
    String string = jSONArray.toString();
    boot.setAppLineIPsJSON(string);   // 直接喂给 Go SDK
}
```

这是一个**由原生 C++ 层（tgnet.so）通过 JNI 反向调用 Java** 的回调——即 app_line_ips 实际上来自 **Telegram 自己的 MTProto 协议层**，是服务端在一个真实建立的 MTProto 会话里，通过某个自定义 TL 对象（历史分析记录标注为 `0xcc1a241e`）主动推送下来的，**与 libgojni.so 的 forwarder-control HMAC 协议完全无关**。

这也解释了：
- 为什么早期"路线A"（MTProto 流量解密提取节点，见 `exdyfb_unpacked/路线A-MTProto解密提取节点.md`）能拿到节点，而且是 18~24 个，量级和 `sdk_forwarder_fixed.json` 一致
- 为什么 forwarder-control 协议永远没被触发——它是一条**备用/未启用**的代码路径，真正生效的是 MTProto 层

### 4.2 定位调用点（libSgzqvwvAiApn.so，C++）

用已有的 Ghidra 工程（`/tmp/ghidra_proj_tgnet2`，image base 同样是 0x100000）搜索字符串 `onIpListReceived` 的交叉引用，找到：

- `FUN_00f0da28`（Ghidra addr）：JNI 方法 ID 缓存初始化函数，缓存了 `onIpListReceived` 等一大串回调方法的 jmethodID
- **`FUN_00f0e9e4`（Ghidra addr 0x00f0e9e4，文件偏移 0xe0e9e4）**：真正的调用点。反编译确认它的逻辑是：
  1. 参数 `x1` 是一个指向 `std::vector<std::string>` 的指针（libc++ 标准布局：`{begin指针, end指针, capacity指针}`，每个元素 24 字节）
  2. 遍历这个 vector，把每个 C++ 字符串转成 Java `jstring`（libc++ 短字符串优化：首字节最低位=0 表示内联短串，长度=首字节>>1，数据从偏移1开始；IP地址字符串这种短串全部走内联）
  3. 构造 Java `String[]` 数组，调用缓存的 jmethodID，触发 `onIpListReceived`

### 4.3 插桩验证（详见第五节），成功捕获明文 IP

对 `FUN_00f0e9e4` 入口打补丁后，在真机上实测捕获到：

```
106.55.6.156
8.134.33.143
103.45.129.234
103.120.90.46
```

与同一时刻读取的 `sdk_forwarder_fixed.json` 内容**完全一致**，交叉验证成功。

---

## 五、二进制插桩技术（ARM64 ELF 运行时补丁）

由于 forwarder-control 协议不可用，且没有 root/frida 可用（这个家族对 frida 有硬反调试，一起 `frida-server` 就导致设备断连重启——已实测确认，以后不要再试），最终采用了**静态 ELF 补丁 + 环形缓冲捕获**的方案，直接在原生代码里插桩截获数据。

### 5.1 补丁原理

1. 用 Ghidra headless 反编译定位目标函数入口的原始指令
2. 复用 ELF 里两个通常不critical 的 Program Header 槽位：
   - `PT_GNU_STACK` → 改造成一个新的 `LOAD` 段，权限 **R+X**（纯代码，不可写），存放插桩用的机器码
   - `PT_NOTE`（`.note.android.ident`，仅288字节的构建标识，运行时不critical）→ 改造成另一个新的 `LOAD` 段，权限 **R+W**（纯数据，不可执行），存放捕获缓冲区
   - **关键教训**：最初把代码和数据放进同一个 **RWX**（可读可写可执行）段，导致 app 必现 Java 层随机崩溃（疑似触发了 Android/SELinux 的 W^X 反利用检测）。拆成两个独立段（分别 R+X 和 R+W）后，问题消失，多次强制重启测试均稳定
3. 在目标函数入口写一条 `b <跳板地址>` 分支指令，跳板里：
   - 用一个 8 字节计数器 + N 个固定大小 slot 的环形缓冲区，无锁递增写入（`ldr→add→str` 三条指令 + `and` 掩码取模），彻底避免"读取时机没踩准、瞬时数据已经被覆盖"的竞态问题（早期版本用单一 slot 覆盖式捕获，屡次错过窗口）
   - 对于捕获 `std::vector` 场景，**不能只存指针**——目标数据是函数栈上的临时对象，函数返回后内存立刻被复用。必须在拦截的那一刻，用一个**限长、防溢出**的拷贝循环（`sub_reg` 算出 `end-begin` 真实长度，`clamp` 到缓冲区上限，`cbz` 防止长度为0时死循环）把原始字节整体拷贝进独立缓冲区
   - 补写被覆盖的原指令语义（用等价的多条指令组合替代，比如把 `stp x29,x30,[sp,#-0x60]!` 这种带写回的复杂寻址，拆成 `sub sp,sp,#0x60` + `stp x29,x30,[sp]` 两条已验证正确的简单指令，避免手写生僻编码出错）
   - 跳回原函数 entry+4 继续正常执行
4. 用 Python 手写 ARM64 指令编码（`adrp/add/ldr/str/ldp/stp/sub/subs/and/lsl/lsr/b/b.cond/cbz` 等），**每次都用 capstone 反汇编回读校验**语义是否符合预期，杜绝手算编码出错（本次会话踩过至少两次手算错误：`lsl` 立即数编码算错、`sub` 编码位置算错，都是靠 capstone 复查抓出来的）
5. 用 `zip -0` 无压缩方式把 patch 后的 .so 写回 APK（保持体积可预测），`uber-apk-signer` 一键做 v1+v2+v3 签名（Android 13+ 强制要求 v2 签名，纯 jarsigner 不够）

### 5.2 关键调试教训

- **W^X 崩溃**：合并代码+数据到同一个 RWX 段会导致 Java 层随机崩溃（表现为无关代码路径的空指针异常、原生线程崩溃），拆分成独立 R+X / R+W 段后彻底消失
- **固定长度拷贝导致 SIGSEGV**：早期版本无脑拷贝固定 480 字节，源缓冲区实际只有 96 字节时会读到未映射内存，崩在插桩代码本身。改成按实际长度限长拷贝后解决
- **地址基准换算**：这批样本的 Ghidra 工程 image base 统一是 `0x100000`，即"Ghidra 地址 - 0x100000 = 文件偏移 = 实际运行时相对地址（因为这些 .so 本身 baddr=0）"，多次因为忘记减这个偏移量导致定位到错误代码，一定要每次显式验证
- **frida 绝对不能用**：这个家族对 frida-server 附加有硬反调试，会直接导致真机断连重启，之前的项目记忆里已经记录过，本次会话再次踩坑确认

### 5.3 工具产物

- `go_src/fwdctl_offline/`：forwarder-control 协议的独立 Go 客户端实现（虽然协议本身未被使用，但代码逻辑经过实机 TLS 指纹分流验证，是准确的协议还原）
- `patch_so.py` / `patch_tgnet.py`（scratchpad 目录）：ARM64 ELF 补丁生成脚本，可参数化复用（改地址常量即可套用到同家族其他样本）
- `hello_logger`（Go 交叉编译的 arm64 静态二进制）：早期尝试用透明 MITM 代理截获 forwarder-control 明文的工具（后来发现协议未启用，此路径废弃，但代码本身可复用于其他需要透明分流+TLS终止的场景）

---

## 六、真机验证结果

### 6.1 成功获取的完整数据（2026-07-27，真机 Pixel 4/华为设备混合测试）

`sdk_forwarder_fixed.json` 实际路径：
```
/sdcard/Android/data/bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns/files/sdk_forwarder_fixed.json
```

历史上曾捕获到的 app_line_ips（不同时间点，节点会轮换，仅作为格式/历史样例）：
```json
{
  "version": 0,
  "fixed": {},
  "app_line_ips": [
    "106.55.6.156", "8.134.33.143", "103.45.129.234", "103.120.90.46"
  ],
  "app_line_port": 30151,
  "saved_at_unix": 1785203651
}
```
（更早的一次读取曾出现 15 个节点，说明池子会随时间/会话增减，**不建议依赖某一次快照当作长期有效清单，应视为动态数据，需要定期重新采集**）

### 6.2 获取该文件需要的条件

1. 设备/环境能真实运行这个 ARM64+armeabi-v7a 的 APK（见第七节，对环境要求很挑）
2. 设备需要 root（该路径在 app 私有外部存储目录下）
3. app 需要真正建立一次 MTProto 会话（不是单纯进程存活，需要联网成功、走完整个 bootstrap 流程）
4. **不需要打任何补丁**——原版 APK 装上、跑起来、root 读文件即可。第五节的插桩纯粹是为了**验证/理解机制**，不是获取节点的必需步骤

---

## 七、"能不能不用真机" —— 模拟器/云手机可行性调查全记录

### 7.1 x86 模拟器：确认无解

APK 只带 `arm64-v8a` + `armeabi-v7a`，核心是 `libgojni.so`（**Go 语言编写、ARM 原生代码**）。x86 模拟器靠 ARM→x86 二进制翻译（Houdini/libndk-translation）执行，Go 运行时的栈增长机制、信号处理等特殊代码模式在翻译层容易踩坑，实测必现 **SIGILL 崩溃**。这是这类样本的普遍已知问题，与 CPU 是否够快、内存是否够大无关，是翻译正确性问题。**结论：任何 x86 模拟器（雷电/MuMu/夜神/Android Studio AVD 的 x86_64 镜像）都跑不了，此路不通，不用再试。**

### 7.2 本地全量 ARM64 软件模拟（QEMU，绕开 Google 官方限制）— 大量进展但未完全跑通

Google 官方 Android Emulator（37.2.1.0）**明确拒绝**在 x86 主机上跑 arm64 系统镜像（`FATAL | Avd's CPU Architecture 'arm64' is not supported by the QEMU2 emulator on x86_64 host`）——这是官方工具主动加的限制，不是配置问题。

绕过方法：直接用原生 `qemu-system-aarch64`（`apt install qemu-system-arm` 装的 6.2.0 版本，需要 sudo）加载同一套 Android AVD 系统镜像文件（`kernel-ranchu` + `ramdisk.img` + `system.img` + `vendor.img` + `userdata.img` + `encryptionkey.img`），走标准 QEMU `virt` 机型 + `virtio-blk`/`virtio-net` 设备（Google 的 "Ranchu" 后端本身就是基于标准 virtio 设计的，兼容性理论上不差）。

**已解决的问题**（按顺序）：
1. Android 内核+四核正常启动，virtio 磁盘正确识别
2. 缺少 "metadata" 分区（Android 10+ 文件级加密元数据）→ 补上 `encryptionkey.img` 作为第4块虚拟磁盘解决
3. 缺少 AVB（验证启动）校验参数 → 从系统镜像目录里的 `VerifiedBootParams.textproto` 抄出对应内核 cmdline 参数
4. 缺少 "super" 动态分区（dynamic partition）导致 `/dev/block/by-name/super` 找不到 → 用 `dtc`（device-tree-compiler，装在独立 conda 环境 `dtcenv` 里）手动给 QEMU 的默认设备树插入一段 Android 专用的 `firmware/android/fstab` 节点，直接把每块 virtio 裸设备映射成对应分区，绕开标准 super 分区流程
5. `system.img`/`vendor.img`/`encryptionkey.img` 实际都各自带一个真实的 GPT 分区表（不是裸文件系统），需要用 `fdisk -l` 读出真实分区偏移，`dd` 切出正确的子分区内容再挂载

**卡住的地方**：`system.img` 的真实文件系统分区内容里发现了 "AVB0" 验证启动元数据签名，但既不是标准 ext4，也排除了 erofs、squashfs——文件系统类型和真实分区边界尚未确认，继续排查需要更专门的 Android 镜像格式知识（如 `avbtool`/`simg2img` 等专用工具的源码级核实），盲目试错的性价比已明显下降，**本次会话在此停止，未最终跑通**。

**结论**：这条路技术上被证明"走得通但没走完"，不是死胡同，只是还差最后一层文件系统格式的确认。相关产物（自定义设备树 dts/dtb、分区提取脚本）保留在 `/tmp/claude-.../scratchpad/qemu_arm64/`，供以后接着查。

### 7.3 云手机实测（华为 Mate 30，安卓10）— 排查出根本原因

用户实际申请的云手机（华为 Mate 30，安卓 10，真 ARM64 硬件）上，APK 装得上但打不开，弹出"当前设备环境不支持运行此应用"。

**排查过程**：抓取 logcat，发现这不是加固壳主动拒绝云手机环境（最初怀疑方向），而是 app 自身代码**对安卓10的兼容性缺陷**导致反复崩溃：

1. **`SecurityException: getUniqueId ... does not meet the requirements to access device identifiers`**——安卓 10 新增的设备标识符访问限制，app 代码没有正确捕获这个新版本才有的异常类型
2. **内嵌广告 SDK 的 `NullPointerException`**（`AdsBean.getData()`）——大概率是广告 SDK 依赖 Google 服务（GMS）获取广告标识符兜底，而**华为 Mate 30 系列本身不带 GMS**（2019年美国贸易制裁后华为首款不含GMS的旗舰），拿不到数据导致空指针
3. 老旧 `org.apache.http.params.BasicHttpParams` 类找不到（安卓6.0+已移除的遗留库，未声明兼容）

**根本原因判定**：不是"云手机被识别"，是**安卓版本（10 太老，新的隐私限制没适配）+ 缺 GMS** 两个环境差异叠加导致的真实代码兼容性 bug，与是否是云手机、是否被检测无关。此前在**安卓13 + 带GMS的 Pixel 4** 上运行同一个 APK 完全正常，形成了直接对照验证。

**给后续选云手机的建议**：
- 优先选安卓 12/13，避开安卓 10 及更早版本
- 必须确认预装 Google 服务框架（GMS），下单前跟客服确认
- 避开华为系机型（默认无GMS），三星/小米等机型相对更容易带GMS
- 需要 root 权限（读取 app 私有存储必需）
- CPU架构本身不用担心，云手机基本都是真 ARM，不会遇到 7.1 节的 SIGILL 问题

---

## 八、结论与后续建议

### 8.1 已经确认有效、可重复的路径

**只要有一个"安卓12/13 + 带GMS + root + 真ARM"的环境（真机或合规云手机），装原版 APK（不需要打任何补丁），跑起来等待联网完成，root 读取 `sdk_forwarder_fixed.json` 即可获得当前的 app_line_ips。** 这是目前唯一验证过完整、稳定、可重复的路径。

### 8.2 已排除/暂不可行的路径

| 路径 | 状态 |
|---|---|
| 纯静态离线获取（不跑APP） | 不可行，app_line_ips 是服务端在活跃MTProto会话里动态推送的，没有"算出来"的办法 |
| forwarder-control HMAC 协议 | 协议逆向完全正确，但运行时从未被调用，此路不通 |
| x86模拟器（雷电/MuMu/夜神/AVD x86镜像） | 确认必现SIGILL崩溃，无解 |
| 本地全量ARM64软件模拟（QEMU） | 技术可行性已大幅验证，卡在最后一步文件系统格式确认，未完全跑通 |
| 华为Mate30云手机 | 安卓版本+GMS缺失导致的兼容性问题，换机型/换安卓版本可能解决 |
| frida/root hook | 触发硬反调试导致设备断连重启，禁用 |

### 8.3 如果要继续深挖"彻底不用设备"这条路

理论上还有一条**未验证**的路径：既然 app_line_ips 来自服务端在**任意**新建立的 MTProto 会话里的主动推送，如果这个推送不特别校验"必须是真实安卓客户端"，那么用纯 Go/Python 手写一个 MTProto 客户端（项目里已有部分实现 `go_src/mtproto_client/`），在这台 x86 Linux 主机上直接做 MTProto 握手，可能完全不需要任何 ARM 环境。这是一个有意义但未经验证的方向，值得后续投入时间验证。

---

## 九、关键文件/路径速查

| 内容 | 路径 |
|---|---|
| 原始APK | `/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/exdyfb_original.apk` |
| 脱壳后的Java源码（JADX产物） | `/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/unpacked_src/` |
| 已恢复的真实dex（内存dump得到） | `/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/dex/classes1~5.dex` |
| forwarder-control协议规范 | `/home/ninini/Agents/APK-Research/reports/forwarder_control_protocol_FINAL.md` |
| 早期节点获取分析（路线A，MTProto解密） | `/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/路线A-MTProto解密提取节点.md` |
| Ghidra工程（libgojni.so） | `/tmp/ghidra_proj_gojni/` |
| Ghidra工程（tgnet.so/libSgzqvwvAiApn.so） | `/tmp/ghidra_proj_tgnet2/` |
| 本次会话的ELF补丁脚本/产物 | `/tmp/claude-*/scratchpad/`（临时目录，未持久化，如需保留应尽快转移） |
| sdk_forwarder_fixed.json（设备上） | `/sdcard/Android/data/bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns/files/sdk_forwarder_fixed.json` |

---

## 十、给未来分析者的经验总结

1. **反编译出来的协议代码不等于运行时真正在用的协议**——必须用运行时插桩/动态验证，不能只靠静态分析下结论，本次在 forwarder-control 协议上栽过跟头
2. **这个家族对 frida 有硬反调试**，接 frida-server 会直接导致设备断连重启，禁用
3. **静态 ELF 补丁是可行的替代方案**，但要注意：代码段和数据段必须物理隔离（不能用RWX，会触发系统层面的反利用检测崩溃）；拷贝任何变长数据都要做边界检查，不能假设固定长度
4. **"打不开"、"环境不支持"这类现象，未必是反检测逻辑主动拒绝**，很可能只是安卓版本兼容性 bug（尤其是安卓10引入的设备标识符访问限制、GMS依赖），排查时要先看崩溃日志里的具体异常类型，不要先入为主假设是"被识别了"
5. 这批加固壳样本的 native 库、Ghidra 工程的地址基准都是统一的 `image base = 0x100000`，换算文件偏移时注意别漏减
