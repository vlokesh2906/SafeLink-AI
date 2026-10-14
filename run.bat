@echo off
set "PROJECT_DIR=%~dp0..\project1"

if not exist "%PROJECT_DIR%\run.bat" (
    echo The updated project was not found at "%PROJECT_DIR%".
    pause
    exit /b 1
)

call "%PROJECT_DIR%\run.bat"
