# iOS 自动加白

## 方案一：Surge / Egern 客户端脚本模块（推荐）

如果你在使用 Surge / Egern，本仓库自带完整模块，支持面板显示、Wi-Fi / 蜂窝网络自适应、network-changed 事件即时触发 + 定时巡检：

👉 模块文件位于本仓库 `surge/po0-firewall-whitelist.sgmodule` 与 `egern/po0-firewall-whitelist.yaml`，已内置直连分流规则 `DOMAIN,www.guguyun.com,DIRECT`。

## 方案二：快捷指令（无需代理 App）

咕咕云白名单加白是一个 GET 请求，iOS 自带的「快捷指令」就能做：

### 1. 创建快捷指令

1. 打开「快捷指令」App → 新建快捷指令
2. 添加操作：`获取 URL 内容`
   - URL：`https://www.guguyun.com/cany_tencentecs/firewall/whitelist?token=你的token`
   - 展开选项：方法选 **GET**
3. 命名为 `GGY加白`，完成

点击运行一次，返回 JSON 里包含 `status: 200` 即为成功。

### 2. 自动化触发

「自动化」标签 → 新建个人自动化：

- **连接 Wi-Fi 时**：触发条件选「Wi-Fi」→ 任意网络 → 运行 `GGY加白`，关掉「运行前询问」
- 可选再建一条「关闭飞行模式」或「充电时」等高频事件作为辅助触发。
