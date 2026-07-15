@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
cd /d "%~dp0"

echo ============================
echo  CVE 漏洞库查询前端 - 启动
echo ============================

rem ---- 选择 Python 解释器（优先 py 启动器，回退 python） ----
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3"
if not defined PY (
  python --version >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo [错误] 未找到 Python，请安装 Python 3.8+ 并加入 PATH。
  pause
  exit /b 1
)

rem ---- 虚拟环境 ----
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] 创建虚拟环境 .venv ...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo [错误] 创建虚拟环境失败。
    pause
    exit /b 1
  )
) else (
  echo [1/3] 虚拟环境已存在，跳过创建。
)

rem ---- 安装依赖 ----
echo [2/3] 安装依赖 ...
".venv\Scripts\python.exe" -m pip install -q --upgrade pip
".venv\Scripts\python.exe" -m pip install -q -r frontend\requirements.txt
if errorlevel 1 (
  echo [错误] 依赖安装失败。
  pause
  exit /b 1
)

rem ---- 环境变量默认值（仅在未设置时填入） ----
if "%CVE_FRONT_HOST%"=="" set "CVE_FRONT_HOST=127.0.0.1"
if "%CVE_FRONT_PORT%"=="" set "CVE_FRONT_PORT=8765"
set "URL=http://%CVE_FRONT_HOST%:%CVE_FRONT_PORT%"

echo [3/3] 启动服务：%URL%
echo （按 Ctrl+C 停止）
echo.

rem ---- 延迟打开浏览器（后台，2 秒后） ----
start "" /b cmd /c "timeout /t 2 /nobreak >nul & start %URL%"

rem ---- 前台运行服务 ----
".venv\Scripts\python.exe" frontend\server.py

endlocal
