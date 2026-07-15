#!/usr/bin/env bash
# CVE 漏洞库查询前端 - 一键启动（Linux / macOS）
set -e

# 切到脚本所在目录（项目根）
cd "$(dirname "$0")"

echo "============================"
echo " CVE 漏洞库查询前端 - 启动"
echo "============================"

# ---- 选择 Python 解释器 ----
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "[错误] 未找到 Python，请安装 Python 3.8+。" >&2
  exit 1
fi

# ---- 虚拟环境 ----
if [ ! -x ".venv/bin/python" ]; then
  echo "[1/3] 创建虚拟环境 .venv ..."
  "$PY" -m venv .venv
else
  echo "[1/3] 虚拟环境已存在，跳过创建。"
fi

# ---- 安装依赖 ----
echo "[2/3] 安装依赖 ..."
".venv/bin/python" -m pip install -q --upgrade pip
".venv/bin/python" -m pip install -q -r frontend/requirements.txt

# ---- 环境变量默认值（仅在未设置时填入） ----
: "${CVE_FRONT_HOST:=127.0.0.1}"
: "${CVE_FRONT_PORT:=8765}"
export CVE_FRONT_HOST CVE_FRONT_PORT CVE_REPORTS_DIR
URL="http://$CVE_FRONT_HOST:$CVE_FRONT_PORT"

echo "[3/3] 启动服务：$URL"
echo "（按 Ctrl+C 停止）"
echo

# ---- 延迟打开浏览器（后台，2 秒后） ----
(
  sleep 2
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then open "$URL" >/dev/null 2>&1 || true
  fi
) &

# ---- 前台运行服务 ----
exec ".venv/bin/python" frontend/server.py
