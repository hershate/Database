# 漏洞数据库 (Vulnerability Database)

> 一个基于公开来源、源驱动构建的 CVE 漏洞深度分析数据库，覆盖 2010–2026 年共 219 条漏洞记录，附带自动生成报告的 Claude Code Skill。

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

## 简介

本仓库是一个**漏洞情报与分析数据库**，收录常见 CVE（Common Vulnerabilities and Exposures）漏洞的深度结构化分析报告。每条记录包含漏洞原理、触发条件、影响范围、PoC 分析（概念性）、修复与防御方案等内容，并附结构化元数据（`metadata.json`）以支持自动化检索与统计。

所有报告均由 [`cve-lookup`](./cve-lookup/) Skill 从 NVD、MITRE、GitHub Security Advisory、Exploit-DB、CISA KEV、CNNVD/CNVD、厂商安全公告等**公开来源**自动检索并生成，遵循**源驱动原则**——内容必须来自搜索结果，禁止编造或推断，所有引用均附完整链接。

> 本项目使用 [Meta-skill](https://github.com/hershate/Meta-skill) 项目构建。

## ⚠️ 免责声明

本仓库面向**防御性安全研究、安全教育、授权渗透测试与漏洞修复参考**。报告中包含的漏洞原理、PoC 分析与利用步骤仅供学习与防御用途，**严禁用于未授权的系统攻击或任何违法活动**。完整免责声明见 [DISCLAIMER.md](./DISCLAIMER.md)。

## 仓库内容

| 目录/文件 | 说明 |
|-----------|------|
| [`CVE-Reports/`](./CVE-Reports/) | 漏洞数据库根目录，按 `<年份>/<CVE-ID>/` 分层组织 |
| [`CVE-Reports/index.md`](./CVE-Reports/index.md) | 数据库汇总索引（含按年份与严重等级统计） |
| [`CVE-Reports/cve-index.json`](./CVE-Reports/cve-index.json) | 所有 CVE 元数据聚合的集中式索引 JSON |
| [`CVE-Reports/lookup-table.md`](./CVE-Reports/lookup-table.md) | 漏洞类型 + 受影响软件对照表（快速检索） |
| [`cve-lookup/`](./cve-lookup/) | 自动查询并生成报告的 Claude Code Skill（v3.1.0） |
| [`LICENSE`](./LICENSE) | Apache License 2.0 |

## 目录结构

```
Database/
├── CVE-Reports/                # 漏洞数据库
│   ├── index.md               # 汇总索引（年份/严重等级统计 + 全量列表）
│   ├── cve-index.json         # 集中式元数据索引
│   ├── lookup-table.md        # 漏洞类型对照表
│   └── <年份>/                # 2010–2026
│       └── CVE-<ID>/
│           ├── report.md      # 完整漏洞分析报告
│           └── metadata.json  # 结构化元数据（CVSS/CWE/标签等）
├── cve-lookup/                # 报告生成 Skill
│   ├── SKILL.md               # Skill 主文件
│   ├── README.md              # Skill 说明
│   ├── scripts/               # Python 辅助脚本（索引/搜索/元数据）
│   └── references/            # 报告模板
├── LICENSE                    # Apache License 2.0
├── README.md                  # 本文件
└── DISCLAIMER.md              # 免责声明
```

## 核心原则

- **源驱动** — 报告内容必须来自公开搜索结果，禁止编造或推断
- **引用可溯** — 所有数据点附完整来源链接，便于核查
- **数据缺失透明化** — 未找到的字段明确标注"暂无数据"及搜索范围
- **结构化** — 每条 CVE 附 `metadata.json`，支持自动化处理与统计
- **深度优先** — 以信息完整性和分析深度为最高优先级，无字数限制

## 如何使用

### 浏览数据库

直接在 [`CVE-Reports/`](./CVE-Reports/) 下按年份/CVE 编号浏览，或查阅：

- [index.md](./CVE-Reports/index.md) — 全量索引与统计
- [cve-index.json](./CVE-Reports/cve-index.json) — 程序化检索
- [lookup-table.md](./CVE-Reports/lookup-table.md) — 按漏洞类型/受影响软件快速定位

### 使用 Skill 生成新报告

`cve-lookup` 是一个 Claude Code Skill，安装后可通过斜杠命令查询并写入新报告：

```
/cve-lookup CVE-2024-3094
```

安装与使用详见 [cve-lookup/README.md](./cve-lookup/README.md)。

## 数据统计

截至 2026-07-13，数据库共收录 **219** 条 CVE，按严重等级分布（节选）：

| 严重等级 | 说明 |
|---------|------|
| 🟥 CRITICAL | 占多数，含大量在野利用漏洞 |
| 🟧 HIGH | 高危漏洞 |
| 🟨 MEDIUM | 中危漏洞 |
| 🟩 LOW | 低危漏洞 |

完整按年份/严重等级统计与全量列表见 [index.md](./CVE-Reports/index.md)。

## 许可证

本项目基于 [Apache License 2.0](./LICENSE) 开源。

## 致谢

- [NVD](https://nvd.nist.gov/) / [MITRE CVE](https://www.cve.org/) — 漏洞编号与基础数据
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — 在野利用编目
- [Exploit-DB](https://www.exploit-db.com/) / [GitHub Security Advisory](https://github.com/advisories) — 公开 PoC 与公告
- 各厂商安全公告与开源社区
