# 安卓自动加白

咕咕云白名单加白是一个标准 GET 请求：

```text
GET https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=你的token
```

在安卓上推荐使用自动化 App 或 Termux。

## 方案一：MacroDroid（免 root）

[MacroDroid](https://play.google.com/store/apps/details?id=com.arlosoft.macrodroid) 免费版支持 5 个宏，足够使用。

创建 2 个宏：

**宏 1 · 网络切换即时加白**
- 触发器：`连接性` → `网络连接变化`（Wi-Fi 连接 / 移动数据连接 都勾选）
- 动作：`网络` → `HTTP 请求`
  - 方法：`GET`
  - URL：`https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=你的token`
- 约束：无

**宏 2 · 定时兜底**
- 触发器：`日期/时间` → `定期触发`，间隔 15 分钟
- 动作：同上的 HTTP GET 请求
- 约束：`网络已连接`

## 方案二：HTTP Shortcuts

[HTTP Shortcuts](https://play.google.com/store/apps/details?id=ch.rmy.android.http_shortcuts)：

1. 新建快捷方式 → 方法 `GET` → URL 填加白地址
2. 设置 → 定时执行 → 每 15 分钟
3. 可配合桌面小部件一键手动加白

## 方案三：Termux

使用仓库根目录的 [install-linux.sh](../install-linux.sh)：

```sh
pkg install -y curl
curl -sSL https://raw.githubusercontent.com/schwarzgelben/ggyfw/main/install-linux.sh | PO0FW_TOKENS="你的token或分享链接" sh
sv-enable crond
```
