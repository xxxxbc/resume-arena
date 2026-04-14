# Resume Arena - ACMer 简历竞技场

ACMer 简历竞赛网站，上传简历后 AI 多维度评分，公开排行榜 PK。

## 功能

- PDF / 图片 / Word 简历上传
- AI 多维度评分（ICPC/CCPC竞赛、实习/项目、学校背景、技术栈、综合素质）
- 雷达图可视化
- 公开排行榜（支持按维度排序）
- 隐私保护（可选隐藏简历详情，文件名匿名化）
- 管理后台（改名、删除、切换公开/隐藏、全量重新评分）
- 评分标准完全公开透明（`/prompt` 页面）
- 安全防护（频率限制、文件magic验证、XSS防护、安全头）

## 技术栈

- **Go 标准库**（零第三方依赖）
- JSON 文件存储
- Bootstrap 5 前端
- 兼容 OpenAI `/v1/responses` API

## 快速开始

```bash
# 1. 克隆项目
git clone https://github.com/xxxxbc/resume-arena.git
cd resume-arena

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env 填入你的 API Key 和管理员密码

# 3. 安装 pdftotext（用于 PDF 文本提取）
# Ubuntu/Debian: apt install poppler-utils
# CentOS/RHEL:   yum install poppler-utils
# macOS:         brew install poppler

# 4. 编译运行
export $(cat .env | xargs)
go build -o resume-arena .
./resume-arena
```

访问 `http://localhost:8080`

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ADMIN_PASSWORD` | 管理后台密码 | `changeme` |
| `ADMIN_TOKEN_SECRET` | Cookie 哈希盐值 | `change-this-secret` |
| `AI_API_URL` | AI API 地址（OpenAI 兼容） | `https://api.openai.com/v1/responses` |
| `AI_API_KEY` | AI API 密钥 | - |
| `AI_MODEL` | AI 模型名称 | `gpt-4o` |
| `PORT` | 监听端口 | `8080` |

## 部署（Nginx + Systemd）

```bash
# systemd service
cat > /etc/systemd/system/resume-arena.service << EOF
[Unit]
Description=Resume Arena
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/resume-arena
EnvironmentFile=/opt/resume-arena/.env
ExecStart=/opt/resume-arena/resume-arena
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now resume-arena
```

```nginx
# Nginx reverse proxy
server {
    listen 80;
    server_name your-domain.com;
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 120s;
    }
}
```

## 评分维度

| 维度 | 权重 | 说明 |
|------|------|------|
| ICPC/CCPC | 30% | 正式算法竞赛成绩（WF > EC Final > 区域赛金 > 银 > 铜） |
| 实习/项目 | 25% | 公司品牌 × 岗位含金量 × 工作内容 |
| 学校背景 | 20% | 国内外高校分层评分 |
| 技术栈 | 15% | 技术广度和深度 |
| 综合素质 | 10% | 简历完整度和专业度 |

## 贡献

欢迎提 Issue 和 PR！
