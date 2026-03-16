@echo off
set MSBUILD_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

if not exist %MSBUILD_PATH% (
    echo [!] MSBuild not found at expected path. Searching...
    for /f "usebackq tokens=*" %%i in (`vswhere.exe -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set MSBUILD_PATH="%%i"
)

if not exist jacker.vcxproj (
    echo [!] jacker.vcxproj not found. Attempting to build files directly...
    cl.exe /EHsc /O2 /MT hijacker_main.cpp obs_ui.cpp obs_hijacker.cpp /I.. /link user32.lib shell32.lib gdi32.lib comctl32.lib advapi32.lib /OUT:jacker.exe
    goto end
)

echo [*] Building Jacker...
%MSBUILD_PATH% jacker.vcxproj /p:Configuration=Release /p:Platform=x64
if %errorlevel% neq 0 (
    echo [-] Build failed!
    pause
    exit /b %errorlevel%
)

:end
echo [+] Build successful!
pause
