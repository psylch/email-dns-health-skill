# Email DNS Health

[English](README.md)

零依赖的邮件 DNS 健康检查技能，适用于 AI 编程助手。仅使用 `dig` 和 `jq` 审计 SPF、DKIM、DMARC、BIMI、MTA-STS 和 MX 记录。自动检测邮件服务商，统计 SPF DNS 查询次数（10 次上限），给出 A-F 健康评级，并提供可操作的修复建议。

## 安装

### 通过 skills.sh（推荐）

```bash
npx skills add psylch/email-dns-health-skill -g -y
```

### 手动安装

```bash
git clone https://github.com/psylch/email-dns-health-skill.git ~/.claude/skills/email-dns-health
```

安装后需重启 agent。

## 前置条件

- 支持 [skills.sh](https://skills.sh/) 的 AI 编程助手（Claude Code、Cursor、Windsurf 等）
- `dig`（DNS 查询工具）
- `jq`（JSON 处理器）

## 使用方法

提及邮件 DNS 相关话题时技能会自动激活。示例：

- "检查 example.com 的邮件 DNS"
- "审计我域名的 SPF/DKIM/DMARC"
- "example.com 用了几次 SPF DNS 查询？"
- "example.com 用的什么邮件服务商？"
- "帮我配置 Google Workspace 的邮件 DNS"
- "修复我域名的邮件投递问题"

### 命令

| 命令 | 说明 |
|------|------|
| `audit <域名>` | 完整邮件 DNS 健康检查，A-F 评级 |
| `check-spf <域名>` | SPF 验证及 DNS 查询计数 |
| `check-dkim <域名> [选择器]` | DKIM 密钥验证（自动检测选择器） |
| `check-dmarc <域名>` | DMARC 策略验证 |
| `detect-provider <域名>` | 从 MX/SPF 检测邮件服务商 |
| `setup-guide <服务商>` | 指定服务商的 DNS 配置指南 |
| `fix <域名>` | 交互式修复流程（支持 Cloudflare API） |

## 许可证

MIT
