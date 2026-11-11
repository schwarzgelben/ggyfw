# GGY 防火墙自动加白与流量监控 (po0fw)

咕咕云 (GGY) 腾讯云/魔方防火墙安全组白名单自动加白与实例流量监控 —— 支持 Surge、Loon、Shadowrocket、Stash、Quantumult X、Egern，以及 PC（Linux / macOS / Windows）、安卓 Termux、软路由（OpenWrt / Kwrt）。

## 原理与最佳实践

- **防火墙加白**：`GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>`
- **流量查询**：`GET https://www.guguyun.com/cany_tencentecs/traffic/query?token=<token>`
- **分流注意**：加白请求、流量查询与公网 IP 嗅探必须直连！已内置 `DIRECT` 分流规则，确保 API 识别的是本机当前真实公网出口 IP，而非代理节点 IP。

### 📊 面板流量自动适配

客户端面板会自动调用咕咕云流量接口，获取实例的**已用流量、总流量、用量占比及月度重置日期**，并在 Surge / Loon / Egern 面板中优雅呈现：
```text
出口 IP: 117.136.32.15 (117.136.32.0/24)
📊 流量: 15.3G / 1000G (1.5%) · 12-01 重置
心跳保活: 持续有效 (刚刚)
```
- 内置 5 分钟智能缓存，避免高频请求增加服务器负担。
- 点击面板“点击刷新”按钮可立即穿透缓存，实时同步最新流量与加白状态。
- 多 token 配置下会自动编号展示各自机器的流量（如 `📊 #1 流量: ...`）。

### 💡 移动网络防断流最佳搭配（方案 1）

咕咕云后台的加白机制特性如下：
- **固定槽位链接 + 手机 UA**：放行请求来源所在整段 `/24` 网段（256 个 IP）。
- **固定槽位链接 + 电脑 UA**：仅放行 `/32` 单 IP。
- **自动轮换链接 / 手动添加当前 IP**：无论何种设备均仅放行 `/32` 单 IP。

因此最佳配置推荐：
1. **手机客户端（Surge 等）**：分配使用**【固定槽位链接】**（默认 UA 为手机），直接放行当前基站整个 `/24` 网段。手机在同区域或同基站漂移时（最后一位跳变）完全不断流！
2. **家庭软路由 / 电脑**：分配使用**【自动轮换链接】**。家庭宽带公网 IP 极为稳定，几天才变一次，`/32` 足够且不浪费固定槽位。
3. **极速自愈与智能节流引擎**：
   - 模块以 2 分钟为周期进行轻量出口探测（直连 3322 / ip.sb / ipip.net / Cloudflare，耗时仅 ~50ms，极省电省流量）。
   - **同网段静默节流**：若探测到当前出口 IP 与上次加白属于同一个 `/24` 网段，且心跳在有效期内，**自动跳过咕咕云加白 API 请求**，零频次消耗、不弹干扰通知。
   - **越界秒级自愈**：一旦手机跨区域切换基站跳出了原 `/24` 网段，脚本立刻主动向咕咕云发起加白并推送通知，无感自愈连接。
   - **Wi-Fi 防占坑 (`skip_wifi`)**：连入家庭 Wi-Fi 时自动跳过上报，保护槽位配额。

## 平台总览

| 平台 | 方案 | 触发方式 |
|---|---|---|
| iOS/Mac 代理客户端 | 本仓库脚本模块：Surge / Loon / Stash / QX / Shadowrocket / Egern | network-changed 即时 + 2分钟探活自愈 + 面板实时流量与刷新 |
| Linux / macOS | 本仓库 shell 脚本 | systemd timer / cron 每 10 分钟，支持 `./po0fw.sh traffic` |
| OpenWrt / Kwrt 软路由 | 本仓库 shell 脚本 | cron + hotplug WAN 重连秒级触发 |
| Windows | 本仓库 PowerShell | 计划任务：10 分钟 + 网络事件，支持流量查询 |
| 安卓 | Termux / MacroDroid / HTTP Shortcuts | 网络切换 + 定时 |

## 代理客户端模块 (Surge 优先)

| 客户端 | 载体 | 配置说明 |
|---|---|---|
| **Surge** | `surge/po0-firewall-whitelist.sgmodule` | 模块参数 `tokens` 填入固定槽位 token 或完整链接（已内置流量查询与面板适配） |
| **Loon** | `loon/po0-firewall-whitelist.plugin` | 插件参数 `tokens` 填入 token 或完整链接 |
| **Stash** | `stash/po0-firewall-whitelist.stoverride` | 覆写内填入 token 或完整链接 |
| **Shadowrocket** | `shadowrocket/po0-firewall-whitelist.srmodule` | 模块文本中替换 `tokens=` |
| **Quantumult X** | `quantumultx/po0-firewall-whitelist.snippet` | BoxJs key `ggy_tokens` 或配置 task |
| **Egern** | `egern/po0-firewall-whitelist.yaml` | 模块参数 `tokens` |

### Surge 安装使用

1. 在 Surge 中安装模块：
   ```text
   https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/surge/po0-firewall-whitelist.sgmodule
   ```
2. 在模块参数设置中：
   - `tokens`: 填入你的咕咕云**固定槽位 token** 或完整分享链接（多台机器用英文逗号分割）。
   - `skip_wifi`: （可选）填入你的家庭 Wi-Fi 名称（SSID，如 `MyHome-5G`），连入时跳过上报。
   - `ua`: （可选，默认 `mobile`）。
3. 模块已内置 `DOMAIN,www.guguyun.com,DIRECT` 以及 IP 探活直连规则，开代理也能正确识别并加白本机出口。

---

## 桌面与软路由安装

### Linux / macOS / 安卓 Termux

```sh
curl -sSL https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/install-linux.sh | PO0FW_TOKENS="你的token或分享链接" sh
```

### OpenWrt / Kwrt 软路由

```sh
curl -sSL https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/openwrt/install-openwrt.sh -o /tmp/i.sh
PO0FW_TOKENS="你的token或分享链接" sh /tmp/i.sh
```

### Windows

管理员 PowerShell：

```powershell
irm https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/windows/install-windows.ps1 -OutFile i.ps1
powershell -ExecutionPolicy Bypass -File i.ps1 -Tokens "你的token或分享链接"
```

## 用法

```sh
po0fw                          # 执行加白并查询流量（读取 /etc/po0fw.conf）
po0fw token1,token2            # 临时指定 token
po0fw traffic                  # 仅查询流量
```
