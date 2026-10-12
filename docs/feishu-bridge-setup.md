# 飞书桥搭建指南(cc-connect → 本机 codex)

> 目标:在飞书里直接和本机的 codex 对话。
> 方案:cc-connect(飞书 WebSocket 长连接,无需公网 IP)驱动本机 codex CLI。
> 来源:cc-connect(codex 生态的飞书桥,WebSocket 长连接,无需公网 IP)。

## 已就绪(2026-10-11 完成)

- cc-connect v1.5.0 已装(npm 全局,npmmirror 源):`cc-connect --help` 可验
- 配置骨架已写:`~/.cc-connect/config.toml`
  - agent = codex,`work_dir = ~/workspace/feishu`(独立沙箱目录,已建)
  - `mode = "yolo"`(bypass 审批——**只有 yolo 下 MCP 工具如 hetu-memory
    才能被自由调用**;独立 work_dir 是主要防线,别把敏感仓放这里)
  - 飞书 platform 段留空,等凭据

## 你要做的两步

### 第一步:拿到飞书应用凭据(二选一)

**路 A · 扫码自动建应用(推荐,机器正常时最快)**:

```bash
cc-connect feishu setup --project feishu
```

会打印二维码+URL,用手机飞书扫码授权,应用自动创建并回填凭据。

> ⚠️ 本机已知问题:`accounts.feishu.cn/oauth/v1/app/registration` 从
> Go 客户端持续超时(curl 直连 3 秒通——疑似 Go 走 IPv6/DNS 的行为
> 差异)。若同样超时,走路 B 或换网络(手机热点)重试。

**路 B · 手动建应用(教程原路,稳妥)**:

1. https://open.feishu.cn → 控制台 → 创建**企业自建应用**
2. 应用能力 → 开启**机器人**
3. 事件订阅 → 选 **WebSocket 长连接** → 添加事件 `im.message.receive_v1`
4. 权限管理 → 勾:
   - `im:message.receive_v1`
   - `im:message:send_as_bot`
   - (可选群聊)`im:message.group_at_msg:readonly` + `im:message.group_msg`
5. **创建版本 → 发布**(最容易漏:不发布不生效)
6. 凭据与基本信息 → 复制 `App ID`(cli_xxx)和 `App Secret`


### 第二步:凭据回填(二选一)

```bash
# 方式 A:命令回填(推荐)
cc-connect feishu bind --project feishu --app cli_xxxxxxxx:你的secret

# 方式 B:手编 ~/.cc-connect/config.toml
[projects.platforms.options]
app_id = "cli_xxxxxxxxxxxx"
app_secret = "xxxxxxxx"
```

## 启动与验证

```bash
# 前台试跑(看日志)
cc-connect
# 期望日志: platform started project=feishu platform=feishu

# 常驻(launchd 用户服务,开机自启+崩溃重拉)——可选
# brew 装的没有 plist,手写一份 ~/Library/LaunchAgents/cc.connect.plist
```

验证:飞书里私聊你的机器人 → "你好,报一下当前目录" → 它用本机 codex
(用你 codex 已配置的模型)回答,工作目录 `~/workspace/feishu`。

## 长记忆在飞书会话里同样生效

hetu-memory 已全局接入(`~/.codex/config.toml`),且 `~/.codex/AGENTS.md`
的召回指令全局生效——飞书会话里 codex 会:

- 开场调 `memory_context` 读你的画像
- "记住 X" → `memory_write` 落盘(与桌面端同一份 `~/.hetu-memory/`)
- "上周做过什么" → `semantic_search` / `episodic_search`

即:**飞书、Desktop、TUI 三端共享同一份长记忆**。

## 给 codex 的桥接说明(建议)

在 `~/workspace/feishu/AGENTS.md` 加一段(cc-connect INSTALL.md 建议):

```markdown
# cc-connect bridge
You are being driven via Feishu. Messages arrive as chat text; keep replies
short and phone-readable (no wide tables/code walls). When a task needs a
repo, tell the user to git clone it into this work_dir first.
```

## 故障排查

| 症状 | 处置 |
|---|---|
| setup 二维码超时 | 本机已知(Go 客户端 vs 飞书注册接口);换网络/热点重试,或走路 B 手动建应用 |
| 发消息机器人不回 | 飞书后台确认应用已**发布**、事件订阅是**长连接模式**、`im.message.receive_v1` 已加 |
| MCP 工具调用被拒 | mode 必须 yolo(exec/桥接下审批策略 never 会拒 MCP 调用) |
| 安全注意 | yolo + 手机消息 = 远程改文件能力;防线是 work_dir 隔离。敏感操作建议在 Desktop 里人工做 |
| 会话里出现过的 secret 会被索引 | v0.3 已有读入口擦除;但**别在 codex 会话里粘贴新 secret**,擦除只防索引不防外发(embedding 上传) |

## 凭据安全

App Secret 发进过聊天/截图 → 去飞书后台重置一次(教程原话)。
