# GGY 防火墙自动加白与流量监控 (po0fw)

咕咕云 (GGY) 腾讯云/魔方防火墙安全组白名单自动加白与实例流量监控 —— 支持 Surge、Loon、Shadowrocket、Stash、Quantumult X、Egern，以及 PC（Linux / macOS / Windows）、安卓 Termux、软路由（OpenWrt / Kwrt）。

## 原理与最佳实践

- **防火墙加白**：`GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>`
- **流量查询**：`GET https://www.guguyun.com/cany_tencentecs/traffic/query?token=<token>`
- **分流注意**：加白请求与流量查询必须直连！已内置 `DIRECT` 分流规则，确保 API 识别的是本机当前真实公网出口 IP，而非代理节点 IP。

### 🎯 固定槽位与轮流写入机制 (`@0` ~ `@4` / `@rotate`)

咕咕云的固定槽位分享链接本质是在 token 末尾追加 `@0`、`@1`、`@2`、`@3`、`@4`（共 5 个固定槽位，没有 5）。
本项目已全面适配**固定写入**与**轮流写入**两种模式：

1. **固定写入模式**：
   - **配置方式**：在 `tokens` 参数填入 `token@0`（或任意 `@0`~`@4`），或设置参数 `slot=0`。
   - **行为**：每次加白均锁定写入该固定槽位，适合多设备各自绑定不同槽位（如手机用 `@0`，平板用 `@1`）。
2. **环形轮流写入模式（移动端最推荐）**：
   - **配置方式**：在 `tokens` 参数填入 `token@rotate`（或 `token@0-4`），或设置参数 `slot=rotate`。
   - **原理**：将 5 个固定槽位作为环形池（FIFO 队列）。
   - **智能轮换**：手机在同个基站 /24 网段内时，保持当前槽位保活；一旦跨区域漂移到新基站（新 /24 网段），**自动推进写入下一个槽位（0 -> 1 -> 2 -> 3 -> 4 -> 0）**！
   - **极致体验**：你最近走过的 5 个基站网段（如家里、公司、地铁、常去咖啡厅等）**同时保持加白生效**，多地点往返完全无需重复等待加白，实现真·零断流！

### 📊 面板流量自动适配

客户端面板会自动调用咕咕云流量接口，获取实例的**已用流量、总流量、用量占比及月度重置日期**，并在 Surge / Loon / Egern 面板中优雅呈现：
```text
出口 IP: 117.136.32.15 (117.136.32.0/24)
槽位状态: 轮换 @0 (共 5 槽)
📊 流量: 15.3G / 1000G (1.5%) · 12-01 重置
心跳保活: 持续有效 (刚刚)
```
- 查询流量时自动剥离 `@0~@4` 槽位后缀，确保流量接口稳定命中。
- 内置 5 分钟智能缓存，避免高频请求增加服务器负担；点击面板“点击刷新”按钮可立即穿透缓存同步最新状态。
- 多 token 配置下会自动编号展示各自机器的流量（如 `📊 #1 流量: ...`）。

### 💡 移动网络防断流最佳搭配（方案 1）

咕咕云后台的加白机制特性如下：
- **固定槽位链接 + 手机 UA**：放行请求来源所在整段 `/24` 网段（256 个 IP）。
- **固定槽位链接 + 电脑 UA**：仅放行 `/32` 单 IP。
- **自动轮换链接 / 手动添加当前 IP**：无论何种设备均仅放行 `/32` 单 IP。

因此最佳配置推荐：
1. **手机客户端（Surge 等）**：分配使用**【固定槽位链接】**（填 `token@rotate` 轮流写入，或 `token@0` 固定写入，默认手机 UA），直接放行当前基站整个 `/24` 网段。手机在同区域或同基站漂移时（最后一位跳变）完全不断流！
2. **家庭软路由 / 电脑**：分配使用**【自动轮换链接】**（不加 `@`）。家庭宽带公网 IP 极为稳定，几天才变一次，`/32` 足够且不浪费固定槽位。
3. **智能节流与保活机制**：
   - 默认 10 分钟定时保活与 `network-changed` 网络变化即时上报，配合客户端面板随时查看实时流量与手动一键刷新。
   - **网络漫游自动自愈**：手机在 Wi-Fi 与蜂窝数据切换或网络变更时立即触发加白，保持连接畅通。
   - **Wi-Fi 防占坑 (`skip_wifi`)**：连入家庭 Wi-Fi 时自动跳过上报，保护槽位配额。

## 平台总览

| 平台 | 方案 | 触发方式 |
|---|---|---|
| iOS/Mac 代理客户端 | 本仓库脚本模块：Surge / Loon / Stash / QX / Shadowrocket / Egern | network-changed 即时 + 定时保活 + 面板实时流量与刷新 |
| Linux / macOS | 本仓库 shell 脚本 | systemd timer / cron 每 10 分钟，支持 `./po0fw.sh traffic` |
| OpenWrt / Kwrt 软路由 | 本仓库 shell 脚本 | cron + hotplug WAN 重连秒级触发 |
| Windows | 本仓库 PowerShell | 计划任务：10 分钟 + 网络事件，支持流量与槽位参数 |
| 安卓 | Termux / MacroDroid / HTTP Shortcuts | 网络切换 + 定时 |

## 代理客户端模块 (Surge 优先)

| 客户端 | 载体 | 配置说明 |
|---|---|---|
| **Surge** | `surge/po0-firewall-whitelist.sgmodule` | 模块参数 `tokens` 填入固定槽位 token（支持 `token@rotate` 或 `token@0`） |
| **Loon** | `loon/po0-firewall-whitelist.plugin` | 插件参数 `tokens` 填入 token 或完整链接，支持 `slot` 槽位管理 |
| **Stash** | `stash/po0-firewall-whitelist.stoverride` | 覆写内填入 token 或完整链接 |
| **Shadowrocket** | `shadowrocket/po0-firewall-whitelist.srmodule` | 模块文本中替换 `tokens=` |
| **Quantumult X** | `quantumultx/po0-firewall-whitelist.snippet` | BoxJs key `ggy_tokens` 或配置 task |
| **Egern** | `egern/po0-firewall-whitelist.yaml` | 模块参数 `tokens` 与 `slot` |

### Surge 安装使用

1. 在 Surge 中安装模块：
   ```text
   https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/surge/po0-firewall-whitelist.sgmodule
   ```
2. 在模块参数设置中：
   - `tokens`: 填入你的咕咕云 token 或链接。推荐填入 `token@rotate` 开启 0~4 槽轮换，或 `token@0` 锁定 0 槽。
   - `slot`: （可选）若 tokens 未加 `@`，可在 slot 参数统一指定 `rotate` 或 `0`。
   - `skip_wifi`: （可选）填入你的家庭 Wi-Fi 名称（SSID，如 `MyHome-5G`），连入时跳过上报。
   - `ua`: （可选，默认 `mobile`）。
3. 模块已内置 `DOMAIN,www.guguyun.com,DIRECT` 直连分流规则，开代理也能正确识别并加白本机出口。

---

## 桌面与软路由安装

### Linux / macOS / 安卓 Termux

```sh
curl -sSL https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/install-linux.sh | PO0FW_TOKENS="你的token@0或分享链接" sh
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
powershell -ExecutionPolicy Bypass -File i.ps1 -Tokens "你的token@0或分享链接"
```

## 用法

```sh
po0fw                          # 执行加白并查询流量（读取 /etc/po0fw.conf）
po0fw token1@0,token2@1        # 临时指定 token 与固定槽位
po0fw traffic                  # 仅查询流量
```
