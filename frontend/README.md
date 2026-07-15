# frontend - 独立的 CVE 漏洞库查询前端

从 NullPhase 项目中拆出「连接 CVE-Reports 漏洞数据库」的前端部分，配一个轻量
FastAPI 后端，成为可独立运行的漏洞库**查询 / 浏览**前端。无需启动原 NullPhase
webapp，单独启动即可查询 `CVE-Reports/` 漏洞库。

## 功能

- **统计**：CVE 总数、严重程度 / 年份 / 漏洞类型分布、受影响组件 Top（条形可视化）
- **搜索**：按关键词（CVE ID / 组件 / 摘要 / 类型）、严重程度、年份、**漏洞类型**、**受影响组件**筛选，分页，支持**列排序**
- **详情**：索引元数据 + 完整 `report.md`（极简 Markdown 渲染），元数据网格 + 复制 CVE ID
- **导出**：下载集中式索引 `cve-index.json`
- **重建索引**：遍历所有 `metadata.json` 重建 `cve-index.json`（自包含，不依赖外部脚本）
- **删除**：删除单条 CVE（目录 + 从索引移除）

> 不含原 webapp 的 **AI 采集**（`cveCollect`）-- 那是依赖 claude CLI + 任务管线
> 的写库操作，与「查询前端」定位不同。

## 目录结构

```
frontend/
├── server.py            # 轻量 FastAPI 后端（读 CVE-Reports/cve-index.json）
├── requirements.txt     # fastapi + uvicorn
├── README.md
└── static/              # 前端静态资源
    ├── index.html       # 查询页面（单页：顶栏 + 统计卡 + 列表卡 + 详情弹窗）
    ├── app.js           # CVE 查询逻辑 + 共享工具（api/toast/escapeHtml/renderMarkdown…）
    ├── style.css        # 精简样式（保留 CVE 页用到的卡片/表格/标签/弹窗等类）
    └── fonts/           # 本地字体（离线可用，零外部依赖）
```

## 快速启动（一键脚本）

项目根目录提供 Windows 与 Linux/macOS 一键启动脚本，自动创建虚拟环境、安装依赖、
启动服务并打开浏览器：

```bash
# Windows（cmd / PowerShell）
start.bat

# Linux / macOS
./start.sh
```

默认监听 `http://127.0.0.1:8765`，浏览器打开即可。`Ctrl+C` 停止服务。

## 手动运行

依赖 Python ≥ 3.8 + fastapi + uvicorn。

```bash
# 1. 创建虚拟环境并安装依赖（首次）
python -m venv .venv        # Linux 上若 python 未指向 Python 3，改用 python3
#   Windows:  .venv\Scripts\python -m pip install -r frontend\requirements.txt
#   Linux:    .venv/bin/python -m pip install -r frontend/requirements.txt

# 2. 启动
#   Windows:  .venv\Scripts\python frontend\server.py
#   Linux:    .venv/bin/python frontend/server.py
```

默认监听 `http://127.0.0.1:8765`，浏览器打开即可。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CVE_REPORTS_DIR` | `../CVE-Reports`（相对 `server.py`） | CVE 漏洞库数据目录（含 `cve-index.json`） |
| `CVE_FRONT_HOST` | `127.0.0.1` | 监听地址 |
| `CVE_FRONT_PORT` | `8765` | 监听端口 |

示例：指定其它数据目录与端口

```bash
# Linux
CVE_REPORTS_DIR=/path/to/CVE-Reports CVE_FRONT_PORT=9000 .venv/bin/python frontend/server.py
# Windows (cmd)
set CVE_REPORTS_DIR=D:\path\to\CVE-Reports && set CVE_FRONT_PORT=9000 && .venv\Scripts\python frontend\server.py
```

## API

与原 NullPhase webapp 的 `/api/cve/*` 保持一致（同源访问，无需 CORS 配置）：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/cve/stats` | 数据库统计 |
| GET | `/api/cve/types` | 漏洞类型列表及计数（供筛选下拉） |
| GET | `/api/cve/software` | 受影响组件列表及计数（供筛选建议） |
| GET | `/api/cve/search?q&severity&year&vuln_type&software&sort&limit&offset` | 搜索（分页 + 排序） |
| GET | `/api/cve/{cve_id}` | 单条详情（元数据 + report.md） |
| GET | `/api/cve/export` | 导出 cve-index.json |
| POST | `/api/cve/rebuild` | 重建 cve-index.json |
| DELETE | `/api/cve/{cve_id}` | 删除单条 CVE |

`sort` 支持：`year_desc`(默认) / `year_asc` / `cvss_desc` / `cvss_asc` /
`severity_desc` / `severity_asc` / `id_asc`。

## 与原项目的关系

- 前端逻辑源自 NullPhase 项目的 `frontend/app.js` 的 `loadIntel` / `cveDbSearch` /
  `cveDetail` / `cveRebuild` / `cveDownloadReport` / `cveDeleteCurrent` 等函数，
  页面源自 NullPhase 项目的 `frontend/nullphase.html` 的「漏洞情报库」页与详情弹窗。
- 后端 `server.py` 源自 NullPhase 项目的 `webapp/routers/cve.py`，去掉了 webapp 专属
  依赖（task_manager / claude CLI / cve-lookup 脚本调用），改为自包含地直接读写
  `CVE-Reports/cve-index.json`。
- 重建索引仅重建 `cve-index.json`（查询前端所依赖的索引）；`index.md` /
  `lookup-table.md` 等文档由 `cve-lookup` skill 维护，查询前端不使用。
- 数据目录 `CVE-Reports/` 由 `cve-lookup` skill 构建维护，本前端只读查询。
