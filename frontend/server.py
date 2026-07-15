"""frontend: 独立的 CVE 漏洞库查询前端 + 轻量后端。

从 NullPhase webapp 中拆出「连接 CVE-Reports 漏洞数据库」的前端部分，配一个最小
FastAPI 后端，直接读取 CVE-Reports/cve-index.json，无需启动原 webapp 即可查询/浏览
漏洞库。

数据目录默认为 ../CVE-Reports（相对本文件），可用环境变量 CVE_REPORTS_DIR 覆盖。
默认监听 127.0.0.1:8765，可用 CVE_FRONT_HOST / CVE_FRONT_PORT 覆盖。

仅提供查询/浏览能力：统计、搜索、详情、导出、重建索引、删除。
（不含原 webapp 的 AI 采集 cveCollect——那是写库操作，与「查询前端」定位不同。）

接口与原 webapp 的 /api/cve/* 保持一致，前端 app.js 可直接复用。
"""
from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s"
)
logger = logging.getLogger("frontend")

# ── 路径配置 ──────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_STATIC = _HERE / "static"
# CVE-Reports 数据库根目录：默认 ../CVE-Reports（相对 frontend），可环境变量覆盖。
_DB_DIR = Path(os.environ.get("CVE_REPORTS_DIR", str(_HERE.parent / "CVE-Reports"))).resolve()
_INDEX_FILE = _DB_DIR / "cve-index.json"

# 与 cve-lookup/scripts/append_to_index.py 一致的严重程度排序
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NONE": 5}


app = FastAPI(title="CVE 漏洞库查询 API", version="1.0")
# 本地查询工具，同源访问为主；放开 CORS 以便必要时跨端口调试。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


# ── 索引读写（自包含，不依赖 cve-lookup 脚本） ──────────────────────────
def _load_index() -> list[dict]:
    """加载 cve-index.json（1 次读，不遍历文件系统）。"""
    if not _INDEX_FILE.exists():
        return []
    try:
        return json.loads(_INDEX_FILE.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("failed to parse %s", _INDEX_FILE)
        return []


def _to_year(v) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def _sort_key(sort: str):
    """构造搜索排序键函数。

    支持 year_desc(默认) / year_asc / cvss_desc / cvss_asc /
    severity_desc / severity_asc / id_asc。降序用取负实现，便于复合键。
    """
    s = (sort or "year_desc").lower()

    def _y(e): return _to_year(e.get("year"))

    def _c(e): return float(e.get("cvss_score") or 0)

    def _so(e): return _SEV_ORDER.get(str(e.get("severity", "")).upper(), 99)

    def _cid(e): return str(e.get("cve_id", ""))

    if s == "year_asc":
        return lambda e: (_y(e), -_c(e))
    if s == "cvss_desc":
        return lambda e: (-_c(e), -_y(e))
    if s == "cvss_asc":
        return lambda e: (_c(e), -_y(e))
    if s == "severity_desc":
        return lambda e: (_so(e), -_c(e))
    if s == "severity_asc":
        return lambda e: (-_so(e), -_c(e))
    if s == "id_asc":
        return _cid
    return lambda e: (-_y(e), -_c(e))  # year_desc：年份降序，同年 CVSS 降序


def _save_index(entries: list[dict]) -> None:
    """按 year 降序、severity 降序排序后写回 cve-index.json。"""
    def _key(e):
        return (
            -_to_year(e.get("year")),
            _SEV_ORDER.get(str(e.get("severity", "")).upper(), 99),
            e.get("cve_id", ""),
        )
    entries.sort(key=_key)
    _INDEX_FILE.write_text(
        json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ── API（与 webapp/routers/cve.py 对齐，去掉 webapp 专属依赖） ───────────
@app.get("/api/cve/stats")
async def cve_stats() -> dict:
    """数据库统计：总数、年份/严重程度/漏洞类型分布、受影响组件 Top。"""
    entries = _load_index()
    if not entries:
        return {
            "total": 0,
            "note": "CVE 数据库未构建（CVE-Reports/cve-index.json 不存在）",
            "years": {}, "severities": {}, "types": {}, "software_top": [],
        }

    year_dist: dict[str, int] = {}
    sev_dist: dict[str, int] = {}
    type_dist: dict[str, int] = {}
    comp_dist: dict[str, int] = {}
    for e in entries:
        y = str(e.get("year", "?"))
        year_dist[y] = year_dist.get(y, 0) + 1
        s = e.get("severity", "UNKNOWN")
        sev_dist[s] = sev_dist.get(s, 0) + 1
        for vt in (e.get("vuln_type") or []):
            type_dist[vt] = type_dist.get(vt, 0) + 1
        for part in str(e.get("affected_component") or "").split("/"):
            c = part.strip()
            if c:
                comp_dist[c] = comp_dist.get(c, 0) + 1

    software_top = sorted(comp_dist.items(), key=lambda x: -x[1])[:15]
    return {
        "total": len(entries),
        "years": dict(sorted(year_dist.items())),
        "severities": sev_dist,
        "types": type_dist,
        "software_top": [{"name": k, "count": v} for k, v in software_top],
        "db_path": str(_DB_DIR),
    }


@app.get("/api/cve/types")
async def cve_types() -> dict:
    """所有漏洞类型及其计数（按计数降序），用于筛选下拉框。"""
    entries = _load_index()
    dist: dict[str, int] = {}
    for e in entries:
        for vt in (e.get("vuln_type") or []):
            dist[vt] = dist.get(vt, 0) + 1
    items = sorted(dist.items(), key=lambda x: (-x[1], x[0]))
    return {"types": [{"name": k, "count": v} for k, v in items]}


@app.get("/api/cve/software")
async def cve_software() -> dict:
    """受影响组件及其计数（按 '/' 拆分，Top 30），用于筛选建议。"""
    entries = _load_index()
    dist: dict[str, int] = {}
    for e in entries:
        for part in str(e.get("affected_component") or "").split("/"):
            c = part.strip()
            if c:
                dist[c] = dist.get(c, 0) + 1
    items = sorted(dist.items(), key=lambda x: (-x[1], x[0]))[:30]
    return {"software": [{"name": k, "count": v} for k, v in items]}


@app.get("/api/cve/search")
async def cve_search(
    q: str = "",
    vuln_type: str = "",
    severity: str = "",
    software: str = "",
    year: str = "",
    sort: str = "year_desc",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """按关键词/漏洞类型/严重程度/组件/年份搜索；支持 offset 分页与排序。"""
    entries = _load_index()
    if not entries:
        return {"results": [], "total": 0, "offset": offset, "limit": limit,
                "note": "CVE 数据库未构建"}

    # 排序：默认年份降序、同年 CVSS 降序（最新最严重的在前）
    entries.sort(key=_sort_key(sort))

    results = entries
    if q:
        ql = q.lower()
        results = [e for e in results if ql in (
            e.get("cve_id", "") + " " + e.get("summary", "") + " "
            + str(e.get("affected_component", "")) + " " + " ".join(e.get("vuln_type") or [])
        ).lower()]
    if vuln_type:
        results = [e for e in results if vuln_type.lower() in [t.lower() for t in (e.get("vuln_type") or [])]]
    if severity:
        results = [e for e in results if (e.get("severity") or "").upper() == severity.upper()]
    if software:
        sl = software.lower()
        results = [e for e in results if sl in (e.get("affected_component") or "").lower()]
    if year:
        results = [e for e in results if str(e.get("year")) == year]

    total = len(results)
    page = results[offset:offset + limit]
    return {"results": page, "total": total, "offset": offset, "limit": limit}


@app.get("/api/cve/export")
async def cve_export() -> Response:
    """导出集中式索引 cve-index.json 为可下载文件。"""
    data = _INDEX_FILE.read_bytes() if _INDEX_FILE.exists() else b"[]"
    return Response(
        data, media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="cve-index.json"'},
    )


@app.post("/api/cve/rebuild")
async def cve_rebuild() -> dict:
    """自包含重建：遍历所有 metadata.json 重建 cve-index.json，与文件系统对齐。

    注：仅重建 cve-index.json（查询前端所依赖的索引）；index.md / lookup-table.md
    这些文档由 cve-lookup skill 维护，查询前端不使用，故不在此重建。
    """
    if not _DB_DIR.exists():
        raise HTTPException(status_code=500, detail="CVE 数据库目录不存在: " + str(_DB_DIR))
    entries: list[dict] = []
    for root, _dirs, files in os.walk(_DB_DIR):
        if Path(root) == _DB_DIR:
            continue  # 跳过顶层索引文件
        if "metadata.json" in files:
            mf = Path(root) / "metadata.json"
            try:
                entries.append(json.loads(mf.read_text(encoding="utf-8")))
            except Exception as e:  # noqa: BLE001
                logger.warning("skip bad metadata %s: %s", mf, e)
    _save_index(entries)
    logger.info("rebuilt cve-index.json: %d entries", len(entries))
    return {"ok": True, "total": len(entries)}


@app.get("/api/cve/{cve_id}")
async def cve_detail(cve_id: str) -> dict:
    """单条 CVE 详情：索引元数据 + 完整 report.md 内容。"""
    cid = cve_id.upper()
    entries = _load_index()
    entry = next((e for e in entries if e.get("cve_id", "").upper() == cid), None)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} 不在数据库中")

    year = str(entry.get("year", ""))
    report_path = _DB_DIR / year / cid / "report.md"
    meta_path = _DB_DIR / year / cid / "metadata.json"

    report = None
    if report_path.exists():
        try:
            report = report_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            report = None

    meta = entry
    if meta_path.exists():
        try:
            meta = {**entry, **json.loads(meta_path.read_text(encoding="utf-8"))}
        except Exception:
            pass

    meta["report"] = report
    meta["report_path"] = str(report_path) if report_path.exists() else None
    meta["has_report"] = report is not None
    return meta


@app.delete("/api/cve/{cve_id}")
async def cve_delete(cve_id: str) -> dict:
    """删除一条 CVE（目录 + 从索引中移除以保持一致）。"""
    cid = cve_id.upper()
    entries = _load_index()
    entry = next((e for e in entries if e.get("cve_id", "").upper() == cid), None)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} 不在数据库中")
    year = str(entry.get("year", ""))
    target = _DB_DIR / year / cid
    if target.exists():
        shutil.rmtree(target)
    remaining = [e for e in entries if e.get("cve_id", "").upper() != cid]
    _save_index(remaining)
    logger.info("deleted %s, %d remaining", cid, len(remaining))
    return {"ok": True, "deleted": cid, "remaining": len(remaining)}


# ── 静态前端（index.html / app.js / style.css / fonts/） ────────────────
# API 路由先注册，最后挂载 StaticFiles 兜底：/api/* 命中路由，其余走静态。
app.mount("/", StaticFiles(directory=str(_STATIC), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("CVE_FRONT_HOST", "127.0.0.1")
    port = int(os.environ.get("CVE_FRONT_PORT", "8765"))
    logger.info("frontend serving DB=%s on http://%s:%d", _DB_DIR, host, port)
    uvicorn.run(app, host=host, port=port)
