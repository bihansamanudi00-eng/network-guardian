@echo off
setlocal
cd /d "%~dp0"
title Network Guardian Setup and Launcher

echo ==============================================
echo       NETWORK GUARDIAN - SETUP AND LAUNCH
echo ==============================================
echo.


set "PYTHON="

REM Prefer the standard Windows Python launcher
where py >nul 2>nul
if not errorlevel 1 set "PYTHON=py"

REM Try the python command
if not defined PYTHON (
    where python >nul 2>nul
    if not errorlevel 1 set "PYTHON=python"
)

REM Check common Python installations
if not defined PYTHON if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PYTHON if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYTHON if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"

REM Thonny fallback
if not defined PYTHON if exist "%LOCALAPPDATA%\Programs\Thonny\python.exe" set "PYTHON=%LOCALAPPDATA%\Programs\Thonny\python.exe"


echo Using Python: %PYTHON%
if not exist ".venv\Scripts\python.exe" (
  echo Creating the private project environment...
  %PYTHON% -m venv .venv
  if errorlevel 1 (
    echo Could not create the environment.
    pause
    exit /b 1
  )
)

echo.
echo Installing/checking all dependencies, including pandas for ML...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto install_failed
".venv\Scripts\python.exe" -m pip install --upgrade -r requirements.txt
if errorlevel 1 goto install_failed

echo.
echo Verifying machine-learning imports...
".venv\Scripts\python.exe" -c "import pandas, joblib, sklearn; from sklearn.ensemble import IsolationForest; print('ML dependencies OK:', 'pandas', pandas.__version__, '| scikit-learn', sklearn.__version__)"
if errorlevel 1 goto ml_failed

echo.
echo Starting Network Guardian...
".venv\Scripts\python.exe" app.py
if errorlevel 1 (
  echo.
  echo Network Guardian closed with an error. Read the message above.
  pause
)
goto end

:install_failed
echo.
echo Dependency installation failed. Check the pip error above.
echo If you are behind a proxy or firewall, pip may be blocked even when websites load.
pause
goto end

:ml_failed
echo.
echo Machine-learning packages could not be imported by this environment.
echo Copy the error above and send it for troubleshooting.
pause
goto end

:end
endlocal
