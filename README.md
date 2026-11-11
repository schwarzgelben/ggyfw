# GGY 防火墙自动加白 (po0fw)

咕咕云 (GGY) 腾讯云/魔方防火墙安全组白名单自动加白 —— 支持 Surge、Loon、Shadowrocket、Stash、Quantumult X、Egern，以及 PC（Linux / macOS / Windows）、安卓 Termux、软路由（OpenWrt / Kwrt）。

## 原理

- 每 10 分钟（+ 网络切换事件）向咕咕云白名单分享端点发起请求：
  `GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=<token>`
- 服务端自动识别当前访问来源 IP 并加入安全组白名单。
- **分流注意**：加白请求必须直连！代理客户端必须添加分流规则 `DOMAIN,www.guguyun.com,DIRECT`，确保 API 识别的是本机当前真实公网 IP，而不是代理节点的出口 IP。

> Token 在咕咕云控制台实例管理页面的防火墙白名单分享链接中获取（即 `?token=` 后面的字符串，或者直接填入完整分享链接）。

## 平台总览

| 平台 | 方案 | 触发方式 |
|---|---|---|
| iOS/Mac 代理客户端 | 本仓库脚本模块：Surge / Loon / Stash / QX / Shadowrocket / Egern | network-changed 即时 + 10 分钟 cron + 面板刷新 |
| Linux / macOS | 本仓库 shell 脚本 | systemd timer / cron 每 10 分钟 |
| OpenWrt / Kwrt 软路由 | 本仓库 shell 脚本 | cron + hotplug WAN 重连秒级触发 |
| Windows | 本仓库 PowerShell | 计划任务：10 分钟 + 网络事件 |
| 安卓 | Termux / MacroDroid / HTTP Shortcuts | 网络切换 + 定时 |

## 代理客户端模块 (Surge 优先)

| 客户端 | 载体 | 配置说明 |
|---|---|---|
| **Surge** | `surge/po0-firewall-whitelist.sgmodule` | 模块参数 `tokens` 填入 token 或完整链接（已内置直连分流） |
| **Loon** | `loon/po0-firewall-whitelist.plugin` | 插件参数 `tokens` 填入 token 或完整链接 |
| **Stash** | `stash/po0-firewall-whitelist.stoverride` | 覆写内填入 token 或完整链接 |
| **Shadowrocket** | `shadowrocket/po0-firewall-whitelist.srmodule` | 模块文本中替换 `tokens=` |
| **Quantumult X** | `quantumultx/po0-firewall-whitelist.snippet` | BoxJs key `ggy_tokens` 或配置 task |
| **Egern** | `egern/po0-firewall-whitelist.yaml` | 模块参数 `tokens` |

### Surge 安装使用

1. 在 Surge 中安装模块：
   ```text
   https://raw.githubusercontent.com/w0ven/po0fw/main/surge/po0-firewall-whitelist.sgmodule
   ```
2. 在模块参数设置中，将 `tokens` 填入你的咕咕云 token 或完整分享链接（多台机器用英文逗号分割）。
3. 模块已内置 `DOMAIN,www.guguyun.com,DIRECT` 规则，开代理也能正确加白本机出口。

---

## 桌面与软路由安装

### Linux / macOS / 安卓 Termux

```sh
curl -sSL https://raw.githubusercontent.com/w0ven/po0fw/main/install-linux.sh | PO0FW_TOKENS="你的token或分享链接" sh
```

### OpenWrt / Kwrt 软路由

```sh
curl -sSL https://raw.githubusercontent.com/w0ven/po0fw/main/openwrt/install-openwrt.sh -o /tmp/i.sh
PO0FW_TOKENS="你的token或分享链接" sh /tmp/i.sh
```

### Windows

管理员 PowerShell：

```powershell
irm https://raw.githubusercontent.com/w0ven/po0fw/main/windows/install-windows.ps1 -OutFile i.ps1
powershell -ExecutionPolicy Bypass -File i.ps1 -Tokens "你的token或分享链接"
```

## 用法

```sh
po0fw                          # 执行加白（读取 /etc/po0fw.conf）
po0fw token1,token2            # 临时指定 token
```
