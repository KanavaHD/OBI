@echo off
set MSBUILD_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

if not exist %MSBUILD_PATH% (
    echo [!] MSBuild not found at expected path. Searching...
    for /f "usebackq tokens=*" %%i in (`vswhere.exe -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set MSBUILD_PATH="%%i"
)

echo [*] Building OBS Monitor Driver...
%MSBUILD_PATH% OBSMonitor.vcxproj /p:Configuration=Release /p:Platform=x64
if %errorlevel% neq 0 (
    echo [-] Build failed!
    pause
    exit /b %errorlevel%
)

echo [+] Build successful! Output: bin\OBSMonitor.sys
pause
