# Falix 多账号自动保活助手

基于 **GitHub Actions + SeleniumBase (CDP/UC Mode) + sing-box** 的 Falix (`client.falixnodes.net`) 自动化巡检与开机工具。支持每天定时登录多个账号，检测服务器是否处于离线状态并自动点击启动，完成后将每个账号的实时截图与汇总报告推送至 Telegram。

---

## 核心特性

* **多账号完全隔离**：一账号一专属 `sing-box` 代理节点与独立临时浏览器目录，结束后自动销毁，杜绝 Cookie、缓存及出口 IP 串号。
* **多协议 sing-box 代理**：支持 `VLESS`（含 Reality / WS / gRPC / HTTPUpgrade）、`VMess`、`Hysteria2`（`hy2://` / `hysteria2://`）、`Trojan`、`Shadowsocks` 及原生 JSON。
* **防检测与自动重试**：开场随机延迟 `3~12s`，账号之间随机空置冷却 `15~40s`，执行顺序随机打乱；纯 CDP 模式配合系统级 GUI 点击应对 Cloudflare Turnstile，单账号异常自动重试 1 次。
* **中英文面板兼容**：同时兼容英文与简体中文界面按钮及状态识别。
* **Telegram 实时推送**：强制直连 Telegram API，单账号发送脱敏图文报告，多账号额外发送汇总清单。

---

## 配置 Secrets

进入私有仓库 **Settings → Secrets and variables → Actions → New repository secret**，添加以下 3 个 Secret：

| Secret 名称 | 必填 | 说明 |
| :--- | :---: | :--- |
| `ACCOUNTS_JSON` | **是** | 多账号与专属代理节点的 JSON 数组（见下方模板） |
| `TG_BOT_TOKEN` | 否 | Telegram Bot Token |
| `TG_CHAT_ID` | 否 | Telegram 接收推送的 Chat ID |

### `ACCOUNTS_JSON` 模板

`server_id` 填控制台网址 `/server/` 后面的数字 ID（例如 `client.falixnodes.net/server/3504253/console` 中的 `3504253`，留空则自动选第一个服务器）；注意每条 `proxy` 链接末尾**不要带回车换行**：

```json
[
  {
    "name": "Falix-1号",
    "email": "account1@outlook.com",
    "password": "your_password_1",
    "server_id": "3504253",
    "proxy": "vless://uuid@example1.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=[www.microsoft.com](https://www.microsoft.com)&fp=chrome&pbk=YOUR_PBK&type=tcp#node1"
  },
  {
    "name": "Falix-2号",
    "email": "account2@outlook.com",
    "password": "your_password_2",
    "server_id": "",
    "proxy": "hy2://password@example2.com:443?sni=example2.com&insecure=1#node2"
  }
]
```

配置完成后进入 **Actions → Falix Multi-Account Keepalive → Run workflow** 手动测试一次，确认 Telegram 收到在线截图即可。
