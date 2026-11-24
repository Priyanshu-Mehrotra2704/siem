@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto usepython
py -3 walkthrough.py
goto done
:usepython
python walkthrough.py
:done
if errorlevel 1 (
 echo.
 echo Startup failed. Please copy the error above.
 pause
)
